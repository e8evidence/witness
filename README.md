# witness

ASD Essential Eight compliance auditing library for Google Workspace and Microsoft 365 tenants.

`witness` runs each of the eight ASD ACSC strategies against the live tenant APIs and scores the results using the **Weakest Link** rule mandated by the [Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model).

## Essential Eight strategies

| Strategy | Abbr | ISM Controls | Description |
|---|---|---|---|
| `application_control` | AC | ISM-0140, ISM-1490 | Applications blocked by allowlist |
| `patch_applications` | PA | ISM-1693, ISM-1704 | App patches applied within one month |
| `macro_settings` | MS | ISM-1671, ISM-1672 | Office macro execution restricted |
| `user_app_hardening` | UH | ISM-1486, ISM-1485 | Browser/PDF hardening controls |
| `restrict_admin` | RA | ISM-1507, ISM-1175 | Privileged accounts use MFA |
| `patch_os` | OS | ISM-1876, ISM-1877 | OS patches applied within two weeks |
| `mfa` | MFA | ISM-1504, ISM-1679 | MFA enforced for all users |
| `backups` | BK | ISM-1511, ISM-1515 | Data backed up and recoverable |

## Maturity levels

| Level | Meaning |
|---|---|
| ML3 | Fully aligned |
| ML2 | Mostly aligned |
| ML1 | Partially aligned |
| ML0 | Not implemented |

The overall tenant score is `MIN(all strategy levels)` — one weak strategy pulls the entire score down.

## Installation

```
go get github.com/e8evidence/witness
```

Requires Go 1.22 or later. No CGO required.

## Quick start

### Google Workspace

```go
import "github.com/e8evidence/witness"

creds := witness.GoogleCredentials{
    CustomerID:   "C0xxxxxxxxx",
    AdminEmail:   "admin@example.com",
    // Either AccessToken (pre-exchanged) or RefreshToken+ClientID+ClientSecret
    AccessToken:  "<pre-exchanged token>",
}

client, err := witness.NewGoogleWorkspaceClient(ctx, creds, slog.Default())
if err != nil { /* ... */ }

mfa,   _ := client.AuditMFA(ctx)
patch, _ := client.AuditPatchOS(ctx)
// ... run any subset of strategies

scorer := witness.NewScorer(slog.Default())
score  := scorer.Score("tenant-id", "Example Co", []witness.StrategyResult{mfa, patch}, witness.ML0)
fmt.Println(score.Overall) // ML2
```

### Microsoft 365

```go
creds := witness.MicrosoftCredentials{
    TenantID:    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    AccessToken: "<pre-exchanged Graph token>",
}

client, err := witness.NewMSGraphClient(ctx, creds, slog.Default())
if err != nil { /* ... */ }

mfa,   _ := client.AuditMFA(ctx)
patch, _ := client.AuditPatching(ctx)
roles, _ := client.AuditAdminRoles(ctx)

scorer := witness.NewScorer(slog.Default())
score  := scorer.Score("tenant-id", "Example Co", []witness.StrategyResult{mfa, patch, roles}, witness.ML0)
```

## Audit methods

### `GoogleWorkspaceClient`

| Method | Strategy | Notes |
|---|---|---|
| `AuditMFA` | `mfa` | Checks 2-Step Verification enrollment per user |
| `AuditPrivileges` | `restrict_admin` | Super Admin accounts with 2SV |
| `AuditChrome` | `patch_applications` | CBCM-enrolled browsers at latest major version; returns `ErrNotAuditable` if no managed browsers |
| `AuditPatchOS` | `patch_os` | ChromeOS devices via Endpoint Verification |
| `AuditMacroSettings` | `macro_settings` | Google Docs script settings |
| `AuditUserAppHardening` | `user_app_hardening` | Chrome safe-browsing and extension policy |
| `AuditAppControl` | `application_control` | Chrome app/extension allowlist enforcement |
| `AuditBackups` | `backups` | Google Vault matter presence |

### `MSGraphClient`

| Method | Strategy | Notes |
|---|---|---|
| `AuditMFA` | `mfa` | Authentication methods per user via Graph |
| `AuditPatching` | `patch_os` | Intune managed device OS patch age (≤14 days for ML2) |
| `AuditAdminRoles` | `restrict_admin` | Global/Privileged/Security/Exchange Administrator accounts |

## Credentials

### `GoogleCredentials`

```go
type GoogleCredentials struct {
    CustomerID   string // Workspace customer ID, e.g. "C0xxxxxxxxx"
    AdminEmail   string // Admin impersonation target for DWD flows
    RefreshToken string // Standard OAuth2 refresh token
    ClientID     string
    ClientSecret string
    AccessToken  string // If set, used directly — no token exchange performed
}
```

### `MicrosoftCredentials`

```go
type MicrosoftCredentials struct {
    TenantID    string // Customer's Azure AD tenant UUID
    AccessToken string // Must be pre-populated before constructing MSGraphClient
}
```

Microsoft 365 tokens must be obtained externally (e.g. via MSAL client-credentials or a GDAP token exchange) and passed in `AccessToken`. No refresh-token exchange is performed by this library.

## Scoring

```go
scorer := witness.NewScorer(log)
score  := scorer.Score(tenantID, tenantName, results, previousML)
```

`Score` applies two levels of weakest-link:

1. **Per-strategy**: each failing `Finding` degrades that strategy by one level (0 failures → ML3, 1 → ML2, 2 → ML1, 3+ → ML0).
2. **Overall**: `MIN(all strategy levels)`.

`Drifted` is set to `true` when the overall level has changed from `previousML` (and `previousML` is not ML0, which is the zero value used for first-run).

## Helpers

```go
// HashPII returns the hex-encoded SHA-256 of a PII value.
// Call this before writing any email address or device ID to a Finding.
witness.HashPII("user@example.com") // → "5e884898..."

// BuildStrategyResult constructs a StrategyResult with ISM refs populated.
result := witness.BuildStrategyResult(witness.StrategyMFA, findings)

// MarshalFindings serialises []Finding to compact JSON for storage.
json, err := witness.MarshalFindings(findings)
```

## Error handling

```go
result, err := client.AuditChrome(ctx)
if errors.Is(err, witness.ErrNotAuditable) {
    // Required service not enrolled — treat as N/A, not a failure
}

var consent *witness.ConsentRevokedError
if errors.As(err, &consent) {
    // Admin consent revoked or not yet granted — surface the Connect flow
    fmt.Printf("tenant %s needs to re-consent (HTTP %d)\n", consent.TenantID, consent.StatusCode)
}

var challenge *witness.ClaimsChallengeError
if errors.As(err, &challenge) {
    // CAE claims challenge — interactive re-authentication required
}
```

| Error | When |
|---|---|
| `ErrNotAuditable` | Required API/service not available for this tenant |
| `*ConsentRevokedError` | Microsoft Graph 401/403 — admin consent revoked or absent |
| `*ClaimsChallengeError` | Microsoft Continuous Access Evaluation re-auth required |

## PII handling

No raw user-identifying data appears in a `Finding`. All email addresses and device identifiers are hashed with SHA-256 via `HashPII` before being written to `Finding.UserHash` or `Finding.Evidence`. The hash is one-way; the original value is never stored by the library.

## CLI tool

`cmd/witness` is a standalone command-line auditor.

```
go install github.com/e8evidence/witness/cmd/witness@latest
```

```
witness google     [flags]   Audit a Google Workspace tenant
witness microsoft  [flags]   Audit a Microsoft 365 tenant

Google flags:
  -customer-id           Workspace customer ID              (env: WITNESS_GOOGLE_CUSTOMER_ID)
  -service-account-json  Path to service account key file   (env: WITNESS_GOOGLE_SERVICE_ACCOUNT_JSON)
  -admin-email           Admin to impersonate for DWD       (env: WITNESS_GOOGLE_ADMIN_EMAIL)
  -access-token          Pre-exchanged token                (env: WITNESS_GOOGLE_ACCESS_TOKEN)
  -refresh-token         OAuth2 refresh token               (env: WITNESS_GOOGLE_REFRESH_TOKEN)
  -client-id             OAuth2 client ID                   (env: WITNESS_GOOGLE_CLIENT_ID)
  -client-secret         OAuth2 client secret               (env: WITNESS_GOOGLE_CLIENT_SECRET)
  -strategy              Strategy to run (default: all)
  -json                  Output JSON
  -verbose               Show individual findings

Microsoft flags:
  -tenant-id      Entra tenant ID           (env: WITNESS_MS_TENANT_ID)
  -access-token   Pre-exchanged token       (env: WITNESS_MS_ACCESS_TOKEN)
  -strategy       Strategy to run (default: all)
  -json           Output JSON
  -verbose        Show individual findings
```

### Authentication options (Google)

**Service account with DWD** — recommended for automated and MSP use cases:

```sh
witness google \
  -customer-id C0xxxxxxxxx \
  -service-account-json /path/to/sa-key.json \
  -admin-email admin@example.com
```

The service account must have domain-wide delegation granted in the customer's Admin console (Security → API Controls → Domain-wide delegation) with the Admin SDK and Chrome Management scopes.

**Pre-exchanged access token** — useful when a token is obtained externally (e.g. via `gcloud` or a DWD resolver):

```sh
witness google \
  -customer-id C0xxxxxxxxx \
  -access-token "$TOKEN"
```

**OAuth2 refresh token** — for direct per-tenant credentials:

```sh
witness google \
  -customer-id C0xxxxxxxxx \
  -refresh-token "$REFRESH_TOKEN" \
  -client-id "$CLIENT_ID" \
  -client-secret "$CLIENT_SECRET"
```

## Development

```
go test ./...
```

Tests use table-driven patterns with HTTP round-trip stubs. No external services or credentials are required.
