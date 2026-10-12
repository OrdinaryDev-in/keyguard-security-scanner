package report

import (
	"embed"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
)

// go:embed bakes these files into the compiled binary, so `keyguard` is a
// single file with no assets to ship alongside it.
//
//go:embed html/report.tmpl html/style.css html/app.js
var assets embed.FS

var tmpl = template.Must(template.New("report.tmpl").Funcs(template.FuncMap{
	"lower":      strings.ToLower,
	"skipReason": SkipReason,
	"upper":      strings.ToUpper,
	"short": func(s string, n int) string {
		if len(s) > n {
			return s[:n]
		}
		return s
	},
}).ParseFS(assets, "html/report.tmpl"))

type htmlGroup struct {
	Key, Title, Blurb string
	Findings          []finding.Finding
}

type htmlData struct {
	*Report
	Groups  []htmlGroup
	RuleIDs []string
	When    string
	CSS     template.CSS
	JS      template.JS
}

// HTML renders a single self-contained page. html/template escapes every
// value for the context it lands in (element text, attribute, URL...), so a
// scanned file containing "<script>" can't inject anything into the report.
func HTML(w io.Writer, r *Report) error {
	css, err := assets.ReadFile("html/style.css")
	if err != nil {
		return err
	}
	js, err := assets.ReadFile("html/app.js")
	if err != nil {
		return err
	}
	d := htmlData{
		Report: r,
		When:   r.ScannedAt.Format("2 Jan 2006, 15:04 MST"),
		CSS:    template.CSS(css), // trusted: our own embedded file
		JS:     template.JS(js),
	}
	meta := []htmlGroup{
		{Key: string(finding.SourceCode), Title: "Secrets in code", Blurb: "Credentials hardcoded in files that will be committed or deployed."},
		{Key: string(finding.SourceConfig), Title: "Risky configuration", Blurb: "Setups that leak secrets even when the code itself looks clean."},
		{Key: string(finding.SourceHistory), Title: "Secrets in git history", Blurb: "Committed at some point. Deleting the line doesn't remove it from history."},
	}
	seen := map[string]bool{}
	for _, g := range meta {
		for _, f := range r.Findings {
			if string(f.Source) == g.Key {
				g.Findings = append(g.Findings, f)
				if !seen[f.RuleID] {
					seen[f.RuleID] = true
					d.RuleIDs = append(d.RuleIDs, f.RuleID)
				}
			}
		}
		if len(g.Findings) > 0 {
			d.Groups = append(d.Groups, g)
		}
	}
	sort.Strings(d.RuleIDs)
	return tmpl.Execute(w, d)
}
