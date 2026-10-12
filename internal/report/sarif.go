package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/OrdinaryDev-in/keyguard-security-scanner/internal/finding"
)

// SARIF (Static Analysis Results Interchange Format) is the JSON format GitHub
// code scanning ingests. Upload it with github/codeql-action/upload-sarif and
// findings show up as alerts in the repo's Security tab and inline on PRs.
// Only the fields GitHub needs are modelled here.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
	Help             sarifText `json:"help"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *sarifRegion `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func level(s finding.Severity) string {
	switch s {
	case finding.High:
		return "error"
	case finding.Medium:
		return "warning"
	}
	return "note"
}

func SARIF(w io.Writer, r *Report) error {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		rules[f.RuleID] = sarifRule{ID: f.RuleID, ShortDescription: sarifText{f.Description}, Help: sarifText{f.Fix}}
		msg := f.Description
		if f.Secret != "" {
			msg += fmt.Sprintf(" (%s)", f.Secret)
		}
		if f.Commit != nil {
			msg += fmt.Sprintf(" — in git history, commit %.8s", f.Commit.SHA)
		}
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		if f.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line, StartColumn: f.Column}
		}
		// Lets GitHub track the same alert across commits even if lines move.
		// Built only from data already in the report (never SecretHash): an
		// unsalted hash of a human-chosen password could be brute-forced offline.
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d|%d", f.RuleID, f.File, f.Secret, f.Line, f.Column)))
		results = append(results, sarifResult{
			RuleID: f.RuleID, Level: level(f.Severity), Message: sarifText{msg},
			Locations:           []sarifLocation{loc},
			PartialFingerprints: map[string]string{"github.com/OrdinaryDev-in/keyguard-security-scanner/v1": hex.EncodeToString(sum[:8])},
		})
	}
	driver := sarifDriver{Name: r.Tool, Version: r.Version}
	for _, rule := range rules {
		driver.Rules = append(driver.Rules, rule)
	}
	sort.Slice(driver.Rules, func(i, j int) bool { return driver.Rules[i].ID < driver.Rules[j].ID })
	if driver.Rules == nil {
		driver.Rules = []sarifRule{}
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
