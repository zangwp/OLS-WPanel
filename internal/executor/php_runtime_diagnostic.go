package executor

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

const lsphpStartupDiagnosticLimit = 16 * 1024

// LSPHPHealthDiagnostic contains only recognized public engine identifiers.
// Raw startup output can contain paths, environment values or credentials and
// is deliberately excluded from the health response and installation logs.
type LSPHPHealthDiagnostic struct {
	Code      string `json:"code"`
	Extension string `json:"extension"`
	Symbol    string `json:"symbol"`
}

var (
	lsphpOPcacheLibraryPattern  = regexp.MustCompile(`(?:^|[/\\\s'"(])opcache\.so(?:[\s:'")]|$)`)
	lsphpUndefinedSymbolPattern = regexp.MustCompile(`(?i:undefined symbol):[ \t]*((?:zend|php)_[A-Za-z0-9_]{1,122})(?:[^A-Za-z0-9_]|$)`)
	lsphpEngineSymbolPattern    = regexp.MustCompile(`^(?:zend|php)_[A-Za-z0-9_]{1,122}$`)
)

func lsphpStartupDiagnostic(output []byte) *LSPHPHealthDiagnostic {
	if len(output) == 0 || len(output) > lsphpHealthOutputLimit || strings.IndexByte(string(output), 0) >= 0 {
		return nil
	}
	if len(output) > lsphpStartupDiagnosticLimit {
		output = output[:lsphpStartupDiagnosticLimit]
		// Do not classify a line cut off at the scan boundary.
		if last := strings.LastIndexByte(string(output), '\n'); last >= 0 {
			output = output[:last]
		} else {
			return nil
		}
	}
	if !utf8.Valid(output) {
		return nil
	}
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(raw)
		if line == "Configuration" || line == "PHP Variables" || line == "Environment" || strings.HasPrefix(line, "$_") {
			break
		}
		if !strings.HasPrefix(line, "Failed loading ") && !strings.HasPrefix(line, "PHP Warning:") &&
			!strings.HasPrefix(line, "Warning:") && !strings.HasPrefix(line, "PHP Startup:") {
			continue
		}
		if !lsphpOPcacheLibraryPattern.MatchString(line) {
			continue
		}
		match := lsphpUndefinedSymbolPattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		return &LSPHPHealthDiagnostic{Code: "extension_abi_mismatch", Extension: "opcache", Symbol: match[1]}
	}
	return nil
}

type lsphpHealthDiagnosticError struct {
	cause      error
	diagnostic LSPHPHealthDiagnostic
}

func (err *lsphpHealthDiagnosticError) Error() string {
	return lsphpHealthDiagnosticSummary(&err.diagnostic)
}

func (err *lsphpHealthDiagnosticError) Unwrap() error { return err.cause }

// WrapLSPHPHealthProbeError preserves a narrowly recognized startup failure
// across a cached read without publishing partial phpinfo or raw stderr.
// Callers must reject output overflow before invoking it.
func WrapLSPHPHealthProbeError(err error, output []byte) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if diagnostic := lsphpStartupDiagnostic(output); diagnostic != nil {
		return &lsphpHealthDiagnosticError{cause: err, diagnostic: *diagnostic}
	}
	return err
}

func lsphpHealthDiagnosticFromError(err error) *LSPHPHealthDiagnostic {
	var diagnosticErr *lsphpHealthDiagnosticError
	if !errors.As(err, &diagnosticErr) {
		return nil
	}
	diagnostic := diagnosticErr.diagnostic
	return &diagnostic
}

func lsphpHealthDiagnosticSummary(diagnostic *LSPHPHealthDiagnostic) string {
	if diagnostic == nil || diagnostic.Code != "extension_abi_mismatch" || diagnostic.Extension != "opcache" || !lsphpEngineSymbolPattern.MatchString(diagnostic.Symbol) {
		return ""
	}
	return "OPcache failed to load: undefined PHP/Zend symbol " + diagnostic.Symbol
}

func withLSPHPHealthDiagnostic(health LSPHPRuntimeHealth, diagnostic *LSPHPHealthDiagnostic) LSPHPRuntimeHealth {
	if lsphpHealthDiagnosticSummary(diagnostic) == "" {
		return health
	}
	health.State, health.Reason, health.Diagnostic = "error", diagnostic.Code, diagnostic
	return health
}
