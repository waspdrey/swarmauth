// Package swarmauth verifies JCT credentials and enforces authorization at
// execution boundaries. It has no dependencies outside the Go standard library.
package swarmauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxTTLSeconds int64 = 30
const maxSafe int64 = 1<<53 - 1

type Error struct{ Code, Message string }

func (e *Error) Error() string           { return e.Code + ": " + e.Message }
func failure(code, message string) error { return &Error{code, message} }

type Constraints struct {
	MaxCalls        *int64
	MaxAmountUSD    *big.Rat
	RateLimitPerMin *int64
	AllowedParams   map[string]any
	SharedBudget    string
}

type Claims struct {
	Iss, Sub, JTI    string
	Capabilities     []string
	IAT, Exp         int64
	Constraints      Constraints
	Delegate, Parent string
}

type parsed struct {
	claims                *Claims
	kid, signature, input []byte
}

func decode(text string) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != text {
		return nil, failure("MALFORMED_TOKEN", "Invalid base64url")
	}
	return data, nil
}

func object(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, failure("MALFORMED_TOKEN", "Invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, failure("MALFORMED_TOKEN", "Expected JSON object")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, failure("MALFORMED_TOKEN", "Trailing JSON data")
	}
	return value, nil
}

func fields(object map[string]any, allowed string) bool {
	names := strings.Split(allowed, ",")
	for name := range object {
		found := false
		for _, candidate := range names {
			if candidate == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func text(value any) (string, bool) { result, ok := value.(string); return result, ok && result != "" }

func integer(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(string(number), 10, 64)
	return parsed, err == nil && parsed >= -maxSafe && parsed <= maxSafe
}

func rational(value any) (*big.Rat, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return nil, false
	}
	floating, err := strconv.ParseFloat(string(number), 64)
	if err != nil || math.IsInf(floating, 0) || math.IsNaN(floating) {
		return nil, false
	}
	result, ok := new(big.Rat).SetString(string(number))
	return result, ok
}

func validJSON(value any) bool {
	switch item := value.(type) {
	case nil, bool, string:
		return true
	case json.Number:
		number, ok := rational(item)
		if !ok {
			return false
		}
		return !number.IsInt() || new(big.Int).Abs(number.Num()).Cmp(big.NewInt(maxSafe)) <= 0
	case []any:
		for _, entry := range item {
			if !validJSON(entry) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, entry := range item {
			if !validJSON(entry) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func parse(token string) (*parsed, error) {
	if len(token) > 65536 {
		return nil, failure("MALFORMED_TOKEN", "Token exceeds 64 KiB limit")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, failure("MALFORMED_TOKEN", "Expected three segments")
	}
	h, err := decode(parts[0])
	if err != nil {
		return nil, err
	}
	p, err := decode(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := decode(parts[2])
	if err != nil {
		return nil, err
	}
	header, err := object(h)
	if err != nil {
		return nil, err
	}
	if header["alg"] != "EdDSA" || header["typ"] != "JCT" {
		return nil, failure("MALFORMED_TOKEN", "Unsupported header")
	}
	kidText, ok := text(header["kid"])
	if !ok {
		return nil, failure("MALFORMED_TOKEN", "Missing kid")
	}
	kid, err := decode(kidText)
	if err != nil || len(kid) != ed25519.PublicKeySize {
		return nil, failure("MALFORMED_TOKEN", "Invalid kid")
	}
	payload, err := object(p)
	if err != nil {
		return nil, err
	}
	if !fields(payload, "iss,sub,capabilities,constraints,iat,exp,jti,dlg,prf") {
		return nil, failure("MALFORMED_TOKEN", "Unknown claim")
	}
	claims := &Claims{}
	if claims.Iss, ok = text(payload["iss"]); !ok {
		return nil, failure("MALFORMED_TOKEN", "Invalid issuer")
	}
	if claims.Sub, ok = text(payload["sub"]); !ok {
		return nil, failure("MALFORMED_TOKEN", "Invalid audience")
	}
	if claims.JTI, ok = text(payload["jti"]); !ok {
		return nil, failure("MALFORMED_TOKEN", "Invalid jti")
	}
	if claims.IAT, ok = integer(payload["iat"]); !ok {
		return nil, failure("MALFORMED_TOKEN", "Invalid iat")
	}
	if claims.Exp, ok = integer(payload["exp"]); !ok || claims.Exp <= claims.IAT {
		return nil, failure("MALFORMED_TOKEN", "Invalid exp")
	}
	capabilities, ok := payload["capabilities"].([]any)
	if !ok || len(capabilities) == 0 {
		return nil, failure("MALFORMED_TOKEN", "Invalid capabilities")
	}
	for _, entry := range capabilities {
		capability, ok := text(entry)
		if !ok {
			return nil, failure("MALFORMED_TOKEN", "Invalid capability")
		}
		claims.Capabilities = append(claims.Capabilities, capability)
	}
	for name, target := range map[string]*string{"dlg": &claims.Delegate, "prf": &claims.Parent} {
		if value := payload[name]; value != nil {
			if *target, ok = text(value); !ok {
				return nil, failure("MALFORMED_TOKEN", "Invalid delegation claim")
			}
		}
	}
	limits := map[string]any{}
	if value, present := payload["constraints"]; present {
		limits, ok = value.(map[string]any)
		if !ok {
			return nil, failure("MALFORMED_TOKEN", "Invalid constraints")
		}
	}
	if !fields(limits, "max_calls,max_amount_usd,rate_limit_per_min,allowed_params,shared_budget") {
		return nil, failure("MALFORMED_TOKEN", "Unknown constraint")
	}
	for name, target := range map[string]**int64{"max_calls": &claims.Constraints.MaxCalls, "rate_limit_per_min": &claims.Constraints.RateLimitPerMin} {
		if value := limits[name]; value != nil {
			number, ok := integer(value)
			if !ok || number < 1 {
				return nil, failure("MALFORMED_TOKEN", "Invalid count")
			}
			*target = &number
		}
	}
	if value := limits["max_amount_usd"]; value != nil {
		amount, ok := rational(value)
		if !ok || amount.Sign() < 0 {
			return nil, failure("MALFORMED_TOKEN", "Invalid amount")
		}
		claims.Constraints.MaxAmountUSD = amount
	}
	claims.Constraints.AllowedParams = map[string]any{}
	if value, present := limits["allowed_params"]; present {
		params, ok := value.(map[string]any)
		if !ok || !validJSON(params) {
			return nil, failure("MALFORMED_TOKEN", "Invalid parameter pins")
		}
		claims.Constraints.AllowedParams = params
	}
	if value := limits["shared_budget"]; value != nil {
		budget, ok := text(value)
		pins := claims.Constraints.AllowedParams
		minor, minorOK := rational(pins["amount_minor"])
		currency, currencyOK := text(pins["currency"])
		validCurrency := currencyOK && len(currency) == 3
		for _, c := range currency {
			if c < 'A' || c > 'Z' {
				validCurrency = false
			}
		}
		if !ok || pins["budget_id"] != budget || !minorOK || minor.Sign() < 0 || !minor.IsInt() || minor.Cmp(big.NewRat(maxSafe, 1)) > 0 || !validCurrency {
			return nil, failure("MALFORMED_TOKEN", "Invalid shared budget pins")
		}
		claims.Constraints.SharedBudget = budget
	}
	return &parsed{claims, kid, signature, []byte(parts[0] + "." + parts[1])}, nil
}

// Registry separates root issuer keys from delegation holder keys.
type Registry struct {
	mu             sync.RWMutex
	roots, holders map[string][][]byte
}

func NewRegistry() *Registry {
	return &Registry{roots: make(map[string][][]byte), holders: make(map[string][][]byte)}
}
func (r *Registry) Register(issuer string, key ed25519.PublicKey, holder, rotate bool) error {
	if issuer == "" || len(key) != ed25519.PublicKeySize {
		return errors.New("Invalid issuer or Ed25519 key")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	target := r.roots
	if holder {
		target = r.holders
	}
	keys := [][]byte{append([]byte(nil), key...)}
	if rotate {
		for _, existing := range target[issuer] {
			if !bytes.Equal(existing, key) {
				keys = append(keys, existing)
			}
		}
	}
	target[issuer] = keys
	return nil
}
func (r *Registry) RevokeIssuer(issuer string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.roots, issuer)
	delete(r.holders, issuer)
}
func (r *Registry) Revoke(issuer string, key ed25519.PublicKey, holder bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	target := r.roots
	if holder {
		target = r.holders
	}
	remaining := [][]byte{}
	for _, existing := range target[issuer] {
		if !bytes.Equal(existing, key) {
			remaining = append(remaining, existing)
		}
	}
	target[issuer] = remaining
}
func (r *Registry) trusted(issuer string, kid []byte, holder bool) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	target := r.roots
	if holder {
		target = r.holders
	}
	keys := target[issuer]
	if len(keys) == 0 {
		return failure("UNKNOWN_ISSUER", "Unknown issuer")
	}
	for _, key := range keys {
		if bytes.Equal(key, kid) {
			return nil
		}
	}
	return failure("INVALID_SIGNATURE", "kid is not trusted for issuer")
}

type RevocationStore interface {
	IsRevoked(jti string) (bool, error)
}
type VerifyOptions struct {
	PublicKey     ed25519.PublicKey
	Registry      *Registry
	Audience      string
	LeewaySeconds *int
	Now           time.Time
	Revocations   RevocationStore
}
type Verified struct {
	Claims *Claims
	Chain  []*Claims
}

func verifyCore(p *parsed, options VerifyOptions, holder bool) error {
	if (options.Registry == nil) == (options.PublicKey == nil) {
		return errors.New("Pass exactly one of PublicKey or Registry")
	}
	if options.Registry != nil {
		if err := options.Registry.trusted(p.claims.Iss, p.kid, holder); err != nil {
			return err
		}
	} else {
		if holder {
			return failure("DELEGATION_VIOLATION", "Delegation requires a registry")
		}
		if !bytes.Equal(options.PublicKey, p.kid) {
			return failure("INVALID_SIGNATURE", "kid does not match trusted key")
		}
	}
	if !ed25519.Verify(ed25519.PublicKey(p.kid), p.input, p.signature) {
		return failure("INVALID_SIGNATURE", "Signature verification failed")
	}
	if p.claims.Exp-p.claims.IAT > MaxTTLSeconds {
		return failure("TOKEN_EXPIRED", "Token TTL exceeds 30 seconds")
	}
	leeway := 2
	if options.LeewaySeconds != nil {
		leeway = *options.LeewaySeconds
	}
	if leeway < 0 || leeway > 2 {
		return errors.New("Leeway must be 0..2")
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	seconds := now.Unix()
	if seconds < p.claims.IAT-int64(leeway) {
		return failure("TOKEN_NOT_YET_VALID", "Token is not yet valid")
	}
	if seconds > p.claims.Exp+int64(leeway) {
		return failure("TOKEN_EXPIRED", "Token expired")
	}
	if options.Revocations != nil {
		revoked, err := options.Revocations.IsRevoked(p.claims.JTI)
		if err != nil {
			return err
		}
		if revoked {
			return failure("TOKEN_REVOKED", "Token revoked")
		}
	}
	return nil
}

func Covered(capability string, granted []string) bool {
	for _, item := range granted {
		if item == capability || strings.HasSuffix(item, ":*") && strings.HasPrefix(capability, strings.TrimSuffix(item, "*")) {
			return true
		}
	}
	return false
}
func wider(child, parent *int64) bool { return parent != nil && (child == nil || *child > *parent) }

func Verify(token string, options VerifyOptions) (*Verified, error) {
	p, err := parse(token)
	if err != nil {
		return nil, err
	}
	if err = verifyCore(p, options, p.claims.Parent != ""); err != nil {
		return nil, err
	}
	c := p.claims
	if options.Audience != "" && options.Audience != c.Sub {
		return nil, failure("AUDIENCE_MISMATCH", "Wrong audience")
	}
	chain := []*Claims{c}
	if c.Parent != "" {
		parent, err := parse(c.Parent)
		if err != nil {
			return nil, err
		}
		a := parent.claims
		if a.Parent != "" {
			return nil, failure("DELEGATION_VIOLATION", "Only one delegation hop is allowed")
		}
		if err = verifyCore(parent, options, false); err != nil {
			return nil, err
		}
		bad := a.Delegate == "" || a.Delegate != c.Iss || c.Delegate != "" || a.JTI == c.JTI || a.Sub != c.Sub || c.IAT < a.IAT || c.Exp > a.Exp
		if a.Constraints.SharedBudget != "" && c.Constraints.SharedBudget != a.Constraints.SharedBudget {
			bad = true
		}
		for _, capability := range c.Capabilities {
			if !Covered(capability, a.Capabilities) {
				bad = true
			}
		}
		if wider(c.Constraints.MaxCalls, a.Constraints.MaxCalls) || wider(c.Constraints.RateLimitPerMin, a.Constraints.RateLimitPerMin) {
			bad = true
		}
		if a.Constraints.MaxAmountUSD != nil && (c.Constraints.MaxAmountUSD == nil || c.Constraints.MaxAmountUSD.Cmp(a.Constraints.MaxAmountUSD) > 0) {
			bad = true
		}
		if checkPins(a.Constraints.AllowedParams, c.Constraints.AllowedParams) != nil {
			bad = true
		}
		if bad {
			return nil, failure("DELEGATION_VIOLATION", "Child widens or changes parent authority")
		}
		chain = []*Claims{a, c}
	} else if c.Delegate != "" {
		return nil, failure("DELEGATION_VIOLATION", "Delegable roots cannot execute")
	}
	return &Verified{c, chain}, nil
}

func checkPins(pins, params map[string]any) error {
	// Marshal actual Go arguments to JSON so native ints, bools, arrays, and
	// maps compare with parsed claims using the same JSON numeric semantics.
	encoded, err := json.Marshal(params)
	if err != nil {
		return failure("CONSTRAINT_VIOLATION", "Arguments must be JSON")
	}
	actual := map[string]any{}
	if params != nil {
		actual, err = object(encoded)
		if err != nil {
			return err
		}
	}
	for key, expected := range pins {
		value, present := actual[key]
		if !present || !equalJSON(expected, value) {
			return failure("CONSTRAINT_VIOLATION", "Pinned parameter mismatch")
		}
	}
	return nil
}
func equalJSON(a, b any) bool {
	if number, ok := a.(json.Number); ok {
		right, ok := b.(json.Number)
		if !ok {
			return false
		}
		x, xok := rational(number)
		y, yok := rational(right)
		return xok && yok && x.Cmp(y) == 0
	}
	switch left := a.(type) {
	case nil:
		return b == nil
	case bool:
		right, ok := b.(bool)
		return ok && left == right
	case string:
		right, ok := b.(string)
		return ok && left == right
	case []any:
		right, ok := b.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for i := range left {
			if !equalJSON(left[i], right[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		right, ok := b.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for key, value := range left {
			other, present := right[key]
			if !present || !equalJSON(value, other) {
				return false
			}
		}
		return true
	}
	return false
}
