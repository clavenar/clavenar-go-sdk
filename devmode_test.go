package clavenar

import "strings"

import "testing"

func TestRenderDenyPanelWithDetail(t *testing.T) {
	d := &Denied{
		ToolName:       "send_email",
		Reasons:        []string{"indirect prompt injection"},
		IntentCategory: "Exfiltration",
		Layer:          "brain",
		CorrelationID:  "abc-123",
		Detail: &VerdictDetail{
			Detectors: []DetectorScore{
				{Detector: "persona_drift", Score: 0.12},
				{Detector: "injection", Score: 0.91, Flagged: true},
			},
			Degraded: []string{"injection"},
		},
	}
	p := RenderDenyPanel(d)
	for _, want := range []string{"send_email", "layer=brain", "correlation=abc-123", "injection", "0.91", "⚠ flagged", "degraded: injection"} {
		if !strings.Contains(p, want) {
			t.Fatalf("panel missing %q:\n%s", want, p)
		}
	}
}

func TestRenderDenyPanelWithoutDetail(t *testing.T) {
	d := &Denied{ToolName: "wire_transfer", Reasons: []string{"policy denied"}, IntentCategory: "Direct Execution"}
	p := RenderDenyPanel(d)
	if !strings.Contains(p, "wire_transfer") || !strings.Contains(p, "CLAVENAR_PROXY_VERBOSE_VERDICTS") {
		t.Fatalf("expected hint panel, got:\n%s", p)
	}
}
