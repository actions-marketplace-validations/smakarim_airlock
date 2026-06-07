package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/syedkarim/snare/internal/config"
	"github.com/syedkarim/snare/internal/engine"
	"github.com/syedkarim/snare/internal/fetcher"
	"github.com/syedkarim/snare/internal/model"
	"github.com/syedkarim/snare/internal/registry"
	"github.com/syedkarim/snare/internal/report"
	"github.com/syedkarim/snare/internal/resolver"
)

var version = "0.0.0-dev"

type auditOpts struct {
	base, head string
	registry   string
	failOn     string
	format     string
	allowlist  string
	out        io.Writer
}

func tierFromString(s string) model.Tier {
	switch s {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium":
		return model.Medium
	case "low":
		return model.Low
	default:
		return model.High
	}
}

func runAudit(o auditOpts) int {
	baseData, err := os.ReadFile(o.base)
	if err != nil {
		fmt.Fprintln(o.out, "snare: read base lockfile:", err)
		return 2
	}
	headData, err := os.ReadFile(o.head)
	if err != nil {
		fmt.Fprintln(o.out, "snare: read head lockfile:", err)
		return 2
	}
	candidates, err := resolver.Diff(baseData, headData)
	if err != nil {
		fmt.Fprintln(o.out, "snare:", err)
		return 2
	}

	var allow *config.Allowlist
	if o.allowlist != "" {
		if data, err := os.ReadFile(o.allowlist); err == nil {
			allow, _ = config.ParseAllowlist(data)
		}
	}

	reg := &registry.HTTPClient{BaseURL: o.registry}
	f := fetcher.New(reg)
	eng := engine.New(engine.Default(time.Now()))

	var results []model.Result
	for _, c := range candidates {
		if allow != nil && allow.Allowed(c.Name, c.Version) {
			continue
		}
		data, err := f.Fetch(c)
		if err != nil {
			results = append(results, model.Result{Candidate: c, Errored: true, ErrMsg: err.Error()})
			continue
		}
		results = append(results, eng.Score(data))
	}

	switch o.format {
	case "json":
		fmt.Fprintln(o.out, report.JSON(results))
	case "sarif":
		fmt.Fprintln(o.out, report.SARIF(results))
	default:
		fmt.Fprint(o.out, report.Human(results))
	}
	return report.ExitCode(results, tierFromString(o.failOn))
}

func main() {
	fs := flag.NewFlagSet("snare", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print version and exit")

	if len(os.Args) >= 2 && os.Args[1] == "audit" {
		var o auditOpts
		o.out = os.Stdout
		af := flag.NewFlagSet("audit", flag.ExitOnError)
		af.StringVar(&o.base, "base", "", "base package-lock.json (PR target)")
		af.StringVar(&o.head, "head", "", "head package-lock.json (PR branch)")
		af.StringVar(&o.registry, "registry", "https://registry.npmjs.org", "npm registry base URL")
		af.StringVar(&o.failOn, "fail-on", "high", "min tier to fail: low|medium|high|critical")
		af.StringVar(&o.format, "format", "human", "output format: human|json|sarif")
		af.StringVar(&o.allowlist, "allowlist", ".snareignore", "allowlist file")
		_ = af.Parse(os.Args[2:])
		if o.base == "" || o.head == "" {
			fmt.Fprintln(os.Stderr, "snare audit: --base and --head are required")
			os.Exit(2)
		}
		os.Exit(runAudit(o))
	}

	_ = fs.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println("snare", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: snare audit --base <lock> --head <lock> [flags]")
	os.Exit(2)
}
