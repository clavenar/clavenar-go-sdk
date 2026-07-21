package clavenar

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPackagedRetrySeparationFixture(t *testing.T) {
	data, err := os.ReadFile("fixtures/retry-separation-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Contract string `json:"contract"`
		Cases    []struct {
			ID             string `json:"id"`
			Automatic      bool   `json:"automaticTransportRetry"`
			MaximumEffects int    `json:"maximumEffectAttempts"`
		} `json:"cases"`
		Invariants map[string]bool `json:"invariants"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Contract != "clavenar.retry-separation/v1" {
		t.Fatalf("contract = %q", fixture.Contract)
	}
	cases := make(map[string]struct {
		automatic bool
		effects   int
	})
	for _, item := range fixture.Cases {
		cases[item.ID] = struct {
			automatic bool
			effects   int
		}{item.Automatic, item.MaximumEffects}
	}
	if got := cases["explicit-side-effect-free-decision"]; !got.automatic || got.effects != 0 {
		t.Fatalf("decision case = %+v", got)
	}
	if got := cases["sdk-registered-executor"]; got.automatic || got.effects != 1 {
		t.Fatalf("executor case = %+v", got)
	}
	if !fixture.Invariants["executorFailuresNeverEnterTransportRetryLoop"] {
		t.Fatal("executor retry invariant missing")
	}
}
