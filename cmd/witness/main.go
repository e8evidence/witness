// witness — command-line auditor for ASD Essential Eight compliance.
//
// Usage:
//
//	witness google     [flags]   Audit a Google Workspace tenant
//	witness microsoft  [flags]   Audit a Microsoft 365 tenant
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/e8evidence/witness"
)

const helpText = `witness — ASD Essential Eight compliance auditor

Usage:
  witness google     [flags]   Audit a Google Workspace tenant
  witness microsoft  [flags]   Audit a Microsoft 365 tenant

Google flags:
  -customer-id    string   Workspace customer ID     (env: WITNESS_GOOGLE_CUSTOMER_ID)
  -access-token   string   Pre-exchanged token       (env: WITNESS_GOOGLE_ACCESS_TOKEN)
  -refresh-token  string   OAuth2 refresh token      (env: WITNESS_GOOGLE_REFRESH_TOKEN)
  -client-id      string   OAuth2 client ID          (env: WITNESS_GOOGLE_CLIENT_ID)
  -client-secret  string   OAuth2 client secret      (env: WITNESS_GOOGLE_CLIENT_SECRET)
  -strategy       string   Strategy to run (default: all)
  -json                    Output JSON
  -verbose                 Show individual findings

Microsoft flags:
  -tenant-id      string   Entra tenant ID           (env: WITNESS_MS_TENANT_ID)
  -access-token   string   Pre-exchanged token       (env: WITNESS_MS_ACCESS_TOKEN)
  -strategy       string   Strategy to run (default: all)
  -json                    Output JSON
  -verbose                 Show individual findings

Strategies: application_control patch_applications macro_settings
            user_app_hardening restrict_admin patch_os mfa backups
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, helpText)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "google":
		err = runGoogle(os.Args[2:])
	case "microsoft":
		err = runMicrosoft(os.Args[2:])
	case "help", "-h", "--help", "-help":
		fmt.Fprint(os.Stdout, helpText)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, helpText)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(val, key string) string {
	if val != "" {
		return val
	}
	return os.Getenv(key)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- Google ------------------------------------------------------------------

func runGoogle(args []string) error {
	fs := flag.NewFlagSet("google", flag.ContinueOnError)
	customerID := fs.String("customer-id", "", "")
	accessToken := fs.String("access-token", "", "")
	refreshToken := fs.String("refresh-token", "", "")
	clientID := fs.String("client-id", "", "")
	clientSecret := fs.String("client-secret", "", "")
	strategy := fs.String("strategy", "all", "")
	jsonOut := fs.Bool("json", false, "")
	verbose := fs.Bool("verbose", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	creds := witness.GoogleCredentials{
		CustomerID:   envOr(*customerID, "WITNESS_GOOGLE_CUSTOMER_ID"),
		AccessToken:  envOr(*accessToken, "WITNESS_GOOGLE_ACCESS_TOKEN"),
		RefreshToken: envOr(*refreshToken, "WITNESS_GOOGLE_REFRESH_TOKEN"),
		ClientID:     envOr(*clientID, "WITNESS_GOOGLE_CLIENT_ID"),
		ClientSecret: envOr(*clientSecret, "WITNESS_GOOGLE_CLIENT_SECRET"),
	}
	if creds.CustomerID == "" {
		return fmt.Errorf("-customer-id or WITNESS_GOOGLE_CUSTOMER_ID is required")
	}
	if creds.AccessToken == "" && (creds.RefreshToken == "" || creds.ClientID == "" || creds.ClientSecret == "") {
		return fmt.Errorf("provide -access-token, or all of -refresh-token / -client-id / -client-secret")
	}

	ctx := context.Background()
	client, err := witness.NewGoogleWorkspaceClient(ctx, creds, discardLogger())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	audits := []auditEntry{
		{witness.StrategyAppControl, client.AuditAppControl},
		{witness.StrategyPatchApps, client.AuditChrome},
		{witness.StrategyMacroSettings, client.AuditMacroSettings},
		{witness.StrategyUserAppHardening, client.AuditUserAppHardening},
		{witness.StrategyRestrictAdmin, client.AuditPrivileges},
		{witness.StrategyPatchOS, client.AuditPatchOS},
		{witness.StrategyMFA, client.AuditMFA},
		{witness.StrategyBackups, client.AuditBackups},
	}

	results, nas, err := runAudits(ctx, audits, *strategy)
	if err != nil {
		return err
	}

	scorer := witness.NewScorer(discardLogger())
	score := scorer.Score(creds.CustomerID, creds.CustomerID, results, witness.ML0)

	if *jsonOut {
		return printJSON(score)
	}
	return printScore(os.Stdout, "Google Workspace", creds.CustomerID, score, nas, *verbose)
}

// --- Microsoft ---------------------------------------------------------------

func runMicrosoft(args []string) error {
	fs := flag.NewFlagSet("microsoft", flag.ContinueOnError)
	tenantID := fs.String("tenant-id", "", "")
	accessToken := fs.String("access-token", "", "")
	strategy := fs.String("strategy", "all", "")
	jsonOut := fs.Bool("json", false, "")
	verbose := fs.Bool("verbose", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	creds := witness.MicrosoftCredentials{
		TenantID:    envOr(*tenantID, "WITNESS_MS_TENANT_ID"),
		AccessToken: envOr(*accessToken, "WITNESS_MS_ACCESS_TOKEN"),
	}
	if creds.TenantID == "" {
		return fmt.Errorf("-tenant-id or WITNESS_MS_TENANT_ID is required")
	}
	if creds.AccessToken == "" {
		return fmt.Errorf("-access-token or WITNESS_MS_ACCESS_TOKEN is required")
	}

	ctx := context.Background()
	client, err := witness.NewMSGraphClient(ctx, creds, discardLogger())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	audits := []auditEntry{
		{witness.StrategyMFA, client.AuditMFA},
		{witness.StrategyPatchOS, client.AuditPatching},
		{witness.StrategyRestrictAdmin, client.AuditAdminRoles},
	}

	results, nas, err := runAudits(ctx, audits, *strategy)
	if err != nil {
		return err
	}

	scorer := witness.NewScorer(discardLogger())
	score := scorer.Score(creds.TenantID, creds.TenantID, results, witness.ML0)

	if *jsonOut {
		return printJSON(score)
	}
	return printScore(os.Stdout, "Microsoft 365", creds.TenantID, score, nas, *verbose)
}

// --- shared audit runner -----------------------------------------------------

type auditEntry struct {
	strategy witness.Strategy
	fn       func(context.Context) (witness.StrategyResult, error)
}

func runAudits(ctx context.Context, audits []auditEntry, filter string) (
	results []witness.StrategyResult,
	notAuditable []witness.Strategy,
	err error,
) {
	for _, a := range audits {
		if filter != "all" && string(a.strategy) != filter {
			continue
		}
		r, auditErr := a.fn(ctx)
		if auditErr != nil {
			if errors.Is(auditErr, witness.ErrNotAuditable) {
				notAuditable = append(notAuditable, a.strategy)
				continue
			}
			return nil, nil, fmt.Errorf("audit %s: %w", a.strategy, auditErr)
		}
		results = append(results, r)
	}
	return results, notAuditable, nil
}

// --- output ------------------------------------------------------------------

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printScore(w io.Writer, provider, tenantID string, score witness.TenantScore, nas []witness.Strategy, verbose bool) error {
	fmt.Fprintf(w, "\nAudit: %s  %s\n", provider, tenantID)
	fmt.Fprintf(w, "Generated: %s\n\n", score.SyncedAt.Format("2006-01-02 15:04 UTC"))

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "STRATEGY\tLEVEL\tPASS\tFAIL")

	for _, r := range score.Strategies {
		pass, fail := countFindings(r.Findings)
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n", r.Strategy, r.Level, pass, fail)

		if verbose {
			tw.Flush()
			printFindings(w, r.Findings)
		}
	}
	for _, s := range nas {
		fmt.Fprintf(tw, "%s\tN/A\t—\t—\n", s)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nOverall: %s\n\n", score.Overall)
	return nil
}

func countFindings(findings []witness.Finding) (pass, fail int) {
	for _, f := range findings {
		if f.Passed {
			pass++
		} else {
			fail++
		}
	}
	return
}

func printFindings(w io.Writer, findings []witness.Finding) {
	for _, f := range findings {
		icon := "  ✓"
		if !f.Passed {
			icon = "  ✗"
		}
		ctrl := ""
		if f.Control != "" {
			ctrl = " [" + f.Control + "]"
		}
		fmt.Fprintf(w, "%s%s  %s\n", icon, ctrl, f.Description)
	}
	fmt.Fprintln(w)
}
