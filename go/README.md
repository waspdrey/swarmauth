# SwarmAuth for Go

Module: `github.com/waspdrey/swarmauth/go`. Requires Go 1.23 or newer. No external
dependencies. This SDK verifies and enforces credentials; issuance stays in
the existing Python/Node/TypeScript issuer implementations.

```go
import (
    "crypto/ed25519"
    "github.com/waspdrey/swarmauth/go"
)

options := swarmauth.EnforcementOptions{
    VerifyOptions: swarmauth.VerifyOptions{
        PublicKey: ed25519.PublicKey(trustedPublicKey),
        Audience: "tool:submit_purchase_order",
    },
    Capability: "tool:submit_purchase_order",
    Params: actualOrderParameters,
    Tracker: swarmauth.NewMemoryUsageTracker(), // create once, reuse across calls
}
claims, err := swarmauth.Authorize(token, options)
if err != nil {
    return err
}
_ = claims // perform the authorized action here
```

`Authorize` requires an audience and capability, checks actual parameter pins,
and requires explicit costs and atomic tracking for bounded calls. USD amounts
are accumulated as exact decimal rationals. An amount is a `*float64`; absence
and explicit zero are distinct. Initialize a tracker once per service, not
once per request.

For delegation, register root and holder keys separately with `NewRegistry`
and `Register(issuer, key, holder, rotate)`. Root and holder key revocation are
supported by `Revoke`, or both are removed by `RevokeIssuer`. Tokens can narrow
one parent grant and cannot redelegate. `Verify` returns the verified chain;
use `Authorize` for actual calls.

`HTTPMiddleware(options, resolve)` authorizes a configured action before
calling your `http.Handler`. The resolver must derive actual parameters and
cost from trusted request processing without performing the action. Successful
handlers can read `ClaimsFromContext`. Duplicate/missing bearer headers are
rejected. Tokens are limited to 64 KiB by this SDK.

The supplied memory tracker is thread-safe and process-local. Distributed
backends implement `UsageTracker.Reserve(chain, amount)` atomically across all
parents and children. Shared-budget tokens are parsed but fail closed unless
the tracker also implements `SupportsSharedBudgets() bool` and enforces the
trusted scope ledger. No Redis backend or signing API is claimed by this SDK.

Development checks:

```sh
cd go
go test -race ./...
go vet ./...
```

The suite consumes the same signed and temporal fixtures as all other SDKs.
The Go module is not published by the Python/npm release workflows. A future
tagged module release uses a `go/vX.Y.Z` tag; use a reviewed repository commit
when evaluating the module before its first tag.
