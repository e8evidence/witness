// Package witness provides ASD Essential Eight compliance auditing for
// Google Workspace and Microsoft 365 tenants.
//
// # Data flow
//
// Each cloud provider exposes an audit client (GoogleWorkspaceClient,
// MSGraphClient). Calling an Audit* method on a client runs one of the eight
// Essential Eight strategies against the live tenant APIs and returns a
// StrategyResult containing individual Findings.
//
// Once all desired strategies have run, pass the results to Scorer.Score to
// apply the ASD "Weakest Link" rule and produce a TenantScore with an overall
// MaturityLevel (ML0–ML3).
//
//	client, _ := witness.NewGoogleWorkspaceClient(ctx, creds, log)
//	mfa, _    := client.AuditMFA(ctx)
//	patch, _  := client.AuditPatchOS(ctx)
//
//	scorer := witness.NewScorer(log)
//	score  := scorer.Score(tenantID, tenantName, []witness.StrategyResult{mfa, patch}, witness.ML0)
//
// # ErrNotAuditable
//
// Audit methods return ErrNotAuditable (via fmt.Errorf("…: %w", ErrNotAuditable))
// when the required API, device class, or service is not available for this
// tenant — for example, CBCM not enrolled or Endpoint Verification not
// deployed. Callers should treat this as "not assessed" rather than a
// compliance failure. The CLI renders these strategies as N/A.
//
// # PII handling
//
// No raw user-identifying data is stored in a Finding. All email addresses
// and device identifiers are passed through HashPII (SHA-256) before being
// written to the UserHash or Evidence fields.
package witness
