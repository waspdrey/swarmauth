package swarmauth

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UsageTracker must reserve the entire verified chain atomically or change
// nothing. Implement this interface with shared durable storage in production.
type UsageTracker interface {
	Reserve(chain []*Claims, amount *big.Rat) error
}
type usage struct {
	calls      int64
	amount     *big.Rat
	timestamps []time.Time
	expiry     int64
}
type MemoryUsageTracker struct {
	mu      sync.Mutex
	entries map[string]usage
}

func NewMemoryUsageTracker() *MemoryUsageTracker {
	return &MemoryUsageTracker{entries: make(map[string]usage)}
}
func (tracker *MemoryUsageTracker) Reserve(chain []*Claims, amount *big.Rat) error {
	if amount == nil || amount.Sign() < 0 {
		return failure("CONSTRAINT_VIOLATION", "Invalid amount")
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	now := time.Now()
	pending := make(map[string]usage)
	for key, entry := range tracker.entries {
		if now.Unix() >= entry.expiry {
			delete(tracker.entries, key)
		}
	}
	for _, claims := range chain {
		if _, present := pending[claims.JTI]; present {
			return failure("CONSTRAINT_VIOLATION", "Duplicate token ids")
		}
		if now.Unix() >= claims.Exp+3 {
			return failure("TOKEN_EXPIRED", "Token expired before reservation")
		}
		current := tracker.entries[claims.JTI]
		spent := new(big.Rat)
		if current.amount != nil {
			spent.Set(current.amount)
		}
		spent.Add(spent, amount)
		recent := []time.Time{}
		for _, stamp := range current.timestamps {
			if !stamp.Before(now.Add(-time.Minute)) {
				recent = append(recent, stamp)
			}
		}
		limits := claims.Constraints
		if limits.MaxCalls != nil && current.calls+1 > *limits.MaxCalls || limits.MaxAmountUSD != nil && spent.Cmp(limits.MaxAmountUSD) > 0 || limits.RateLimitPerMin != nil && int64(len(recent))+1 > *limits.RateLimitPerMin {
			return failure("CONSTRAINT_VIOLATION", "Token allowance exhausted")
		}
		pending[claims.JTI] = usage{current.calls + 1, spent, append(recent, now), claims.Exp + 3}
	}
	if len(pending) == 0 {
		return errors.New("Empty authorization chain")
	}
	for key, entry := range pending {
		tracker.entries[key] = entry
	}
	return nil
}

type EnforcementOptions struct {
	VerifyOptions
	Capability string
	Params     map[string]any
	Amount     *float64
	Tracker    UsageTracker
}

func Authorize(token string, options EnforcementOptions) (*Claims, error) {
	if options.Capability == "" || options.Audience == "" {
		return nil, errors.New("Authorize requires audience and capability")
	}
	verified, err := Verify(token, options.VerifyOptions)
	if err != nil {
		return nil, err
	}
	c := verified.Claims
	if !Covered(options.Capability, c.Capabilities) {
		return nil, failure("CAPABILITY_VIOLATION", "Missing capability")
	}
	if err = checkPins(c.Constraints.AllowedParams, options.Params); err != nil {
		return nil, err
	}
	stateful := c.Constraints.MaxCalls != nil || c.Constraints.MaxAmountUSD != nil || c.Constraints.RateLimitPerMin != nil
	if c.Constraints.SharedBudget != "" {
		budgetTracker, ok := options.Tracker.(interface{ SupportsSharedBudgets() bool })
		if !ok || !budgetTracker.SupportsSharedBudgets() {
			return nil, failure("CONSTRAINT_VIOLATION", "Shared budget requires a budget-aware tracker")
		}
	}
	if stateful && options.Tracker == nil {
		return nil, failure("CONSTRAINT_VIOLATION", "Usage tracker required")
	}
	if c.Constraints.MaxAmountUSD != nil && options.Amount == nil {
		return nil, failure("CONSTRAINT_VIOLATION", "Explicit amount required")
	}
	amount := new(big.Rat)
	if options.Amount != nil {
		value := *options.Amount
		if math.IsInf(value, 0) || math.IsNaN(value) || value < 0 {
			return nil, failure("CONSTRAINT_VIOLATION", "Invalid amount")
		}
		var ok bool
		amount, ok = new(big.Rat).SetString(strconv.FormatFloat(value, 'g', -1, 64))
		if !ok {
			return nil, failure("CONSTRAINT_VIOLATION", "Invalid amount")
		}
	}
	if options.Tracker != nil {
		if err = options.Tracker.Reserve(verified.Chain, amount); err != nil {
			return nil, err
		}
	}
	return c, nil
}

type claimsKey struct{}

func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(*Claims)
	return claims, ok
}

// HTTPMiddleware authorizes a configured action before dispatch. Resolve must
// derive the actual action parameters/cost from trusted request processing.
// Keep it free of side effects. Tokens never supply their own trust keys.
func HTTPMiddleware(options EnforcementOptions, resolve func(*http.Request) (map[string]any, *float64, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headers := r.Header.Values("Authorization")
			token := ""
			if len(headers) == 1 && len(headers[0]) <= 65543 {
				parts := strings.SplitN(headers[0], " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && !strings.ContainsAny(parts[1], " \t\r\n") {
					token = parts[1]
				}
			}
			if token == "" {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Invalid bearer credential", http.StatusUnauthorized)
				return
			}
			requestOptions := options
			if resolve != nil {
				params, amount, err := resolve(r)
				if err != nil {
					http.Error(w, "Invalid action parameters", http.StatusBadRequest)
					return
				}
				requestOptions.Params = params
				requestOptions.Amount = amount
			}
			claims, err := Authorize(token, requestOptions)
			if err != nil {
				code := "AUTHORIZATION_FAILED"
				var authError *Error
				if errors.As(err, &authError) {
					code = authError.Code
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
		})
	}
}
