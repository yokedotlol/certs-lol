// certs — fast, local TLS scanning. Same engine as certs.lol.
//
// Usage:
//
//	certs <target> [targets...]       Scan one or more targets
//	certs --mx <domain>               Resolve MX records and scan mail servers
//	certs compare <a> <b>             Side-by-side comparison
//	certs list-rules                  Show available assertion rules
//	certs version                     Print version info
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yokedotlol/certs-lol/cli/assert"
	"github.com/yokedotlol/certs-lol/cli/bulk"
	"github.com/yokedotlol/certs-lol/cli/cmd"
	"github.com/yokedotlol/certs-lol/cli/output"
	"github.com/yokedotlol/certs-lol/enrich"
	"github.com/yokedotlol/certs-lol/probe"
)

// Injected at build time via ldflags.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	// Check for subcommands
	switch args[0] {
	case "compare":
		cfg, err := parseArgs(args[1:])
		if err != nil {
			fatal(err)
		}
		if cfg.noColor {
			output.DisableColors()
		}
		opts := buildScanOpts(cfg)
		code := cmd.RunCompare(os.Stdout, cfg.targets, opts)
		os.Exit(code)

	case "list-rules":
		printRules()
		return

	case "version":
		fmt.Printf("certs %s (%s)\nhttps://certs.lol\n", version, commit)
		return

	case "help", "--help", "-h":
		usage()
		return

	default:
		// Fall through to scan mode
	}

	cfg, err := parseArgs(args)
	if err != nil {
		fatal(err)
	}

	if cfg.noColor {
		output.DisableColors()
	}

	// Load config file (additive with flags)
	_, fileCfg := assert.FindConfig(cfg.configFile)
	if fileCfg != nil {
		if fileCfg.Profile != "" && cfg.profile == "" {
			cfg.profile = fileCfg.Profile
		}
		cfg.asserts = append(fileCfg.Assertions, cfg.asserts...)
		if len(cfg.targets) == 0 {
			cfg.targets = append(cfg.targets, fileCfg.Targets...)
		}
	}

	// Expand profile
	if cfg.profile != "" {
		profileAsserts := assert.ExpandProfile(cfg.profile)
		if profileAsserts == nil {
			fmt.Fprintf(os.Stderr, "error: unknown profile %q (available: %s)\n",
				cfg.profile, strings.Join(assert.ProfileNames(), ", "))
			os.Exit(2)
		}
		cfg.asserts = append(profileAsserts, cfg.asserts...)
	}

	// Parse assertions
	var assertions []assert.Assertion
	if len(cfg.asserts) > 0 {
		assertions, err = assert.ParseAll(cfg.asserts)
		if err != nil {
			fatal(err)
		}
	}

	// Read targets from file
	if cfg.file != "" {
		fileTargets, err := readTargetFile(cfg.file)
		if err != nil {
			fatal(err)
		}
		cfg.targets = append(cfg.targets, fileTargets...)
	}

	if len(cfg.targets) == 0 && !cfg.mx {
		fmt.Fprintf(os.Stderr, "error: no targets specified\n")
		usage()
		os.Exit(2)
	}

	opts := buildScanOpts(cfg)
	opts.Assertions = assertions

	// MX mode
	if cfg.mx {
		code := cmd.RunMXScan(os.Stdout, cfg.targets, opts)
		os.Exit(code)
	}

	// Bulk mode (file or multiple targets)
	if cfg.file != "" || len(cfg.targets) > 3 {
		scanFn := func(target string) (probe.SSLResult, *enrich.Result) {
			probeOpts := probe.CLIOptions()
			probeOpts.Port = cfg.port
			probeOpts.TimeoutSec = int(opts.Timeout.Seconds())
			probeOpts.StartTLSProto = cfg.startTLS
			if cfg.noPrivate {
				probeOpts.AllowPrivate = false
			}
			if probeOpts.StartTLSProto == "" {
				probeOpts.StartTLSProto = probe.DetectProtocol(cfg.port)
			}

			result := probe.Scan(target, probeOpts)
			var enrichResult *enrich.Result
			if !cfg.probeOnly && result.Error == nil {
				enrichOpts := enrich.DefaultOptions()
				enrichOpts.Port = cfg.port
				r := enrich.Enrich(target, enrichOpts)
				ciphers := make([]enrich.CipherForCompliance, len(result.Ciphers))
				for i, c := range result.Ciphers {
					ciphers[i] = enrich.CipherForCompliance{Name: c.Name, Strength: c.Strength}
				}
				r.Compliance = enrich.EvaluateCompliance(enrich.ComplianceInput{
					Protocols:      result.Protocols,
					Ciphers:        ciphers,
					KeyAlg:         result.KeyAlg,
					KeySize:        result.KeySize,
					ForwardSecrecy: result.ForwardSecrecy,
					ChainValid:     result.ChainValid,
					DaysRemaining:  result.DaysRemaining,
					OCSPStapling:   result.OCSPStapling,
					HSTSEnabled:    r.HSTS.Enabled,
				})
				enrichResult = &r
			}
			return result, enrichResult
		}

		bulkOpts := bulk.Options{
			Workers:    cfg.workers,
			OutDir:     cfg.out,
			Quiet:      cfg.quiet,
			Assertions: assertions,
			Version:    version,
			Profile:    cfg.profile,
		}
		code := bulk.Run(os.Stdout, cfg.targets, scanFn, bulkOpts)
		os.Exit(code)
	}

	// Single / few targets scan
	code := cmd.RunScan(os.Stdout, cfg.targets, opts)
	os.Exit(code)
}

// ─── Arg parsing ────────────────────────────────────────────────────

type config struct {
	jsonOut    bool
	table      bool
	gradeOnly  bool
	probeOnly  bool
	noPrivate  bool
	quiet      bool
	noColor    bool
	mx         bool
	verbose    bool
	port       int
	timeout    string
	startTLS   string
	file       string
	out        string
	workers    int
	profile    string
	configFile string
	asserts    []string
	targets    []string
}

func parseArgs(args []string) (*config, error) {
	cfg := &config{
		port:    443,
		workers: 10,
		timeout: "15s",
	}

	i := 0
	for i < len(args) {
		arg := args[i]

		// Handle --flag=value syntax
		eqIdx := -1
		if strings.HasPrefix(arg, "--") {
			eqIdx = strings.Index(arg, "=")
		}
		var eqVal string
		if eqIdx > 0 {
			eqVal = arg[eqIdx+1:]
			arg = arg[:eqIdx]
		}

		switch arg {
		case "--json", "-j":
			cfg.jsonOut = true
		case "--table", "-t":
			cfg.table = true
		case "--grade", "-g":
			cfg.gradeOnly = true
		case "--probe-only":
			cfg.probeOnly = true
		case "--no-private":
			cfg.noPrivate = true
		case "--quiet", "-q":
			cfg.quiet = true
		case "--no-color":
			cfg.noColor = true
		case "--verbose", "-v":
			cfg.verbose = true
		case "--mx":
			cfg.mx = true

		case "--assert", "-a":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.asserts = append(cfg.asserts, v)

		case "--profile", "-P":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.profile = v

		case "--config", "-c":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.configFile = v

		case "--port", "-p":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", v)
			}
			cfg.port = n

		case "--timeout":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.timeout = v

		case "--starttls":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.startTLS = v

		case "--file", "-f":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.file = v

		case "--out", "-o":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			cfg.out = v

		case "--workers", "-w":
			v, err := getVal(args, &i, eqIdx, eqVal, arg)
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("invalid workers: %s", v)
			}
			cfg.workers = n

		default:
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unknown flag: %s", arg)
			}
			cfg.targets = append(cfg.targets, arg)
		}

		i++
	}

	return cfg, nil
}

func getVal(args []string, i *int, eqIdx int, eqVal, flag string) (string, error) {
	if eqIdx > 0 {
		return eqVal, nil
	}
	*i++
	if *i >= len(args) {
		return "", fmt.Errorf("%s requires a value", flag)
	}
	return args[*i], nil
}

func buildScanOpts(cfg *config) cmd.ScanOptions {
	timeout, err := time.ParseDuration(cfg.timeout)
	if err != nil {
		timeout = 15 * time.Second
	}

	return cmd.ScanOptions{
		Port:          cfg.port,
		Timeout:       timeout,
		StartTLSProto: cfg.startTLS,
		ProbeOnly:     cfg.probeOnly,
		NoPrivate:     cfg.noPrivate,
		JSON:          cfg.jsonOut,
		Table:         cfg.table,
		GradeOnly:     cfg.gradeOnly,
		Verbose:       cfg.verbose,
		Version:       version,
	}
}

func readTargetFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading target file: %w", err)
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(2)
}

func usage() {
	fmt.Fprintf(os.Stderr, `certs %s — fast, local TLS scanning

Usage:
  certs <target> [targets...]         Scan one or more domains/IPs
  certs --mx <domain>                 Scan all MX mail servers
  certs compare <a> <b>               Side-by-side comparison
  certs list-rules                    List assertion rules
  certs version                       Version info

Output:
  -j, --json                          JSON output (default when piped)
  -t, --table                         Force pretty output
  -g, --grade                         Print only the letter grade
      --no-color                      Disable ANSI colors (also: NO_COLOR env)

Scanning:
  -p, --port <N>                      Port (default 443)
      --timeout <dur>                 Connection timeout (default 15s)
      --starttls <proto>              Force STARTTLS protocol (smtp/imap/pop3)
      --probe-only                    Skip enrichment (HSTS/DNS/compliance)
      --no-private                    Block private/reserved IPs
  -v, --verbose                       Show connection diagnostics
      --mx                            Resolve MX records and scan mail servers

Assertions:
  -a, --assert <rule>                 Assertion rule (repeatable)
  -P, --profile <name>               Named assertion profile
  -c, --config <path>                Config file (default .certs.yaml)

Bulk:
  -f, --file <path>                   Read targets from file
  -o, --out <dir>                     Write results to directory
  -w, --workers <N>                   Concurrent workers (default 10)
  -q, --quiet                         Suppress progress

Exit codes:
  0    Scan succeeded, all assertions passed
  1    Scan succeeded, assertion(s) failed
  2    Usage error
  3    Scan/connection error

https://certs.lol/cli
`, version)
}

func printRules() {
	byCategory := assert.RulesByCategory()

	fmt.Println()
	for _, cat := range assert.RuleCategories {
		rules, ok := byCategory[cat]
		if !ok || len(rules) == 0 {
			continue
		}

		fmt.Printf("  %s\n", cat)
		for _, r := range rules {
			name := r.Name
			if r.ArgsHint != "" {
				name += " " + r.ArgsHint
			}
			fmt.Printf("    %-30s %s\n", name, r.Description)
		}
		fmt.Println()
	}

	fmt.Println("  Profiles")
	for _, name := range assert.ProfileNames() {
		assertions := assert.Profiles[name]
		fmt.Printf("    %-30s %s\n", name, strings.Join(assertions, ", "))
	}
	fmt.Println()
}
