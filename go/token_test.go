package swarmauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func signed(t *testing.T, key ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JCT", "kid": encode(key.Public().(ed25519.PublicKey))})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := encode(header) + "." + encode(payload)
	return input + "." + encode(ed25519.Sign(key, []byte(input)))
}
func baseClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": "issuer", "sub": "tool:x", "capabilities": []string{"tool:x"}, "iat": now, "exp": now + 30, "jti": "id", "constraints": map[string]any{}}
}

func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/test-vectors/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		PublicKey string `json:"issuer_public_key_hex"`
		Seed      string `json:"issuer_private_key_seed_hex"`
		Vectors   []struct {
			Name        string                     `json:"name"`
			Valid       bool                       `json:"valid"`
			Code        string                     `json:"error_code"`
			Token       string                     `json:"token"`
			Claims      map[string]json.RawMessage `json:"claims"`
			DelegateKey string                     `json:"delegate_public_key_hex"`
			Root        string                     `json:"root_iss"`
			Delegate    string                     `json:"delegate_iss"`
		} `json:"vectors"`
		Temporal []struct {
			Name   string `json:"name"`
			IAT    int64  `json:"iat"`
			Exp    int64  `json:"exp"`
			Leeway int    `json:"leeway_seconds"`
			Now    int64  `json:"now"`
			Valid  bool   `json:"expect_valid"`
			Code   string `json:"error_code"`
		} `json:"temporal_test_cases"`
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	publicKey, _ := hex.DecodeString(data.PublicKey)
	seed, _ := hex.DecodeString(data.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	for _, vector := range data.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			options := VerifyOptions{PublicKey: publicKey, Now: time.Unix(1700000010, 0)}
			if value, ok := vector.Claims["iat"]; ok {
				var iat int64
				if json.Unmarshal(value, &iat) == nil {
					options.Now = time.Unix(iat+10, 0)
				}
			}
			if vector.DelegateKey != "" {
				registry := NewRegistry()
				delegate, _ := hex.DecodeString(vector.DelegateKey)
				_ = registry.Register(vector.Root, publicKey, false, false)
				_ = registry.Register(vector.Delegate, delegate, true, false)
				options.PublicKey = nil
				options.Registry = registry
			}
			result, err := Verify(vector.Token, options)
			if vector.Valid {
				if err != nil || result == nil {
					t.Fatalf("valid vector rejected: %v", err)
				}
			} else {
				requireCode(t, err, vector.Code)
			}
		})
	}
	for _, test := range data.Temporal {
		t.Run(test.Name, func(t *testing.T) {
			claims := baseClaims()
			claims["iat"] = test.IAT
			claims["exp"] = test.Exp
			_, err := Verify(signed(t, key, claims), VerifyOptions{PublicKey: publicKey, Now: time.Unix(test.Now, 0), LeewaySeconds: &test.Leeway})
			if test.Valid {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireCode(t, err, test.Code)
			}
		})
	}
}

func TestSingleUseConcurrencyAndParameterTypes(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	claims := baseClaims()
	claims["constraints"] = map[string]any{"max_calls": 1, "allowed_params": map[string]any{"flag": true}}
	token := signed(t, key, claims)
	tracker := NewMemoryUsageTracker()
	options := EnforcementOptions{VerifyOptions: VerifyOptions{PublicKey: public, Audience: "tool:x"}, Capability: "tool:x", Tracker: tracker, Params: map[string]any{"flag": 1}}
	_, err := Authorize(token, options)
	requireCode(t, err, "CONSTRAINT_VIOLATION")
	options.Params = map[string]any{"flag": true}
	var successes atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 24; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := Authorize(token, options); err == nil {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("single-use executed %d times", successes.Load())
	}
}

func TestExactBudgetAndMissingAmount(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	claims := baseClaims()
	claims["constraints"] = map[string]any{"max_amount_usd": 0.3}
	token := signed(t, key, claims)
	options := EnforcementOptions{VerifyOptions: VerifyOptions{PublicKey: public, Audience: "tool:x"}, Capability: "tool:x", Tracker: NewMemoryUsageTracker()}
	_, err := Authorize(token, options)
	requireCode(t, err, "CONSTRAINT_VIOLATION")
	for _, amount := range []float64{0.1, 0.2} {
		options.Amount = &amount
		if _, err := Authorize(token, options); err != nil {
			t.Fatal(err)
		}
	}
	excess := 1e-12
	options.Amount = &excess
	_, err = Authorize(token, options)
	requireCode(t, err, "CONSTRAINT_VIOLATION")
}

func TestDelegatedSiblingsShareParentAllowance(t *testing.T) {
	rootPublic, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	holderPublic, holderKey, _ := ed25519.GenerateKey(rand.Reader)
	parent := baseClaims()
	parent["dlg"] = "worker"
	parent["constraints"] = map[string]any{"max_calls": 1}
	parentToken := signed(t, rootKey, parent)
	registry := NewRegistry()
	_ = registry.Register("issuer", rootPublic, false, false)
	_ = registry.Register("worker", holderPublic, true, false)
	options := EnforcementOptions{VerifyOptions: VerifyOptions{Registry: registry, Audience: "tool:x"}, Capability: "tool:x", Tracker: NewMemoryUsageTracker()}
	for i := 0; i < 2; i++ {
		child := baseClaims()
		child["iss"] = "worker"
		child["jti"] = "child-" + strconv.Itoa(i)
		child["prf"] = parentToken
		child["constraints"] = map[string]any{"max_calls": 1}
		_, err := Authorize(signed(t, holderKey, child), options)
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			requireCode(t, err, "CONSTRAINT_VIOLATION")
		}
	}
	registry.RevokeIssuer("worker")
	_, err := Verify(parentToken, options.VerifyOptions)
	requireCode(t, err, "DELEGATION_VIOLATION")
}

func TestHTTPBoundary(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	claims := baseClaims()
	claims["constraints"] = map[string]any{"max_calls": 1}
	token := signed(t, key, claims)
	var executed atomic.Int32
	options := EnforcementOptions{VerifyOptions: VerifyOptions{PublicKey: public, Audience: "tool:x"}, Capability: "tool:x", Tracker: NewMemoryUsageTracker()}
	handler := HTTPMiddleware(options, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ClaimsFromContext(r.Context()); !ok {
			t.Error("missing claims")
		}
		executed.Add(1)
		w.WriteHeader(204)
	}))
	for _, expected := range []int{204, 403} {
		request := httptest.NewRequest("POST", "/execute", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != expected {
			t.Fatalf("status %d, want %d", response.Code, expected)
		}
	}
	if executed.Load() != 1 {
		t.Fatal("replay executed")
	}
	request := httptest.NewRequest("POST", "/execute", nil)
	request.Header.Add("Authorization", "Bearer "+token)
	request.Header.Add("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal("duplicate credentials accepted")
	}
}

func TestSharedBudgetsRejectOrdinaryTrackers(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	claims := baseClaims()
	pins := map[string]any{"budget_id": "task", "currency": "GHS", "amount_minor": 10}
	claims["constraints"] = map[string]any{"shared_budget": "task", "allowed_params": pins}
	options := EnforcementOptions{VerifyOptions: VerifyOptions{PublicKey: public, Audience: "tool:x"}, Capability: "tool:x", Params: pins, Tracker: NewMemoryUsageTracker()}
	_, err := Authorize(signed(t, key, claims), options)
	requireCode(t, err, "CONSTRAINT_VIOLATION")
}
