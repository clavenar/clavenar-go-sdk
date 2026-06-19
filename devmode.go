package clavenar

import (
	"fmt"
	"os"
	"strings"
)

// RenderDenyPanel renders a denied tool call's verbose-verdict breakdown
// as a readable console panel — the developer-mode view. Returns the
// string; the SDK writes it to stderr (via emitDenyPanel) when
// Options.DevMode is set. Pure (no I/O) so it's unit-testable; falls back
// to a hint when the gateway didn't include Detail (verbose-verdicts off).
func RenderDenyPanel(d *Denied) string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "━━ clavenar denied: %s ━━", d.ToolName)

	var meta []string
	if d.Layer != "" {
		meta = append(meta, "layer="+d.Layer)
	}
	if d.IntentCategory != "" {
		meta = append(meta, "intent="+d.IntentCategory)
	}
	if d.CorrelationID != "" {
		meta = append(meta, "correlation="+d.CorrelationID)
	}
	if len(meta) > 0 {
		fmt.Fprintf(&b, "\n  %s", strings.Join(meta, "  "))
	}

	if len(d.Reasons) > 0 {
		b.WriteString("\n  reasons:")
		for _, r := range d.Reasons {
			fmt.Fprintf(&b, "\n    - %s", r)
		}
	}

	if d.Detail != nil && len(d.Detail.Detectors) > 0 {
		b.WriteString("\n  detectors:")
		for _, det := range d.Detail.Detectors {
			flag := ""
			if det.Flagged {
				flag = "  ⚠ flagged"
			}
			fmt.Fprintf(&b, "\n    %-22s%.2f%s", det.Detector, det.Score, flag)
		}
		if len(d.Detail.Degraded) > 0 {
			fmt.Fprintf(&b, "\n  degraded: %s", strings.Join(d.Detail.Degraded, ", "))
		}
	} else {
		b.WriteString("\n  (no per-detector detail — run the gateway with CLAVENAR_PROXY_VERBOSE_VERDICTS=true)")
	}

	if d.CorrelationID != "" {
		fmt.Fprintf(&b, "\n  trace: look up correlation %s in the console audit trail", d.CorrelationID)
	}
	return b.String()
}

// emitDenyPanel writes the dev-mode deny panel to stderr. Best-effort.
func emitDenyPanel(d *Denied) {
	fmt.Fprintln(os.Stderr, RenderDenyPanel(d))
}
