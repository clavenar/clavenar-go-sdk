package clavenar

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPackagedClientMigrationFixture(t *testing.T) {
	data, err := os.ReadFile("fixtures/client-migration-v1.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Contract            string            `json:"contract"`
		MinimumSafeVersions map[string]string `json:"minimumSafeVersions"`
		LegacyRejection     struct {
			HTTPStatus      int  `json:"httpStatus"`
			Executable      bool `json:"executable"`
			ToolEffectCount int  `json:"toolEffectCount"`
		} `json:"legacyRejection"`
		Invariants map[string]bool `json:"invariants"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Contract != "clavenar.client-migration/v1" {
		t.Fatalf("contract = %q", fixture.Contract)
	}
	if fixture.MinimumSafeVersions["go"] != "1.3.0" {
		t.Fatalf("minimum Go version = %q", fixture.MinimumSafeVersions["go"])
	}
	if fixture.LegacyRejection.HTTPStatus != 426 || fixture.LegacyRejection.Executable || fixture.LegacyRejection.ToolEffectCount != 0 {
		t.Fatalf("legacy rejection = %+v", fixture.LegacyRejection)
	}
	if !fixture.Invariants["legacyInspectionCannotExecute"] {
		t.Fatal("legacy inspection invariant missing")
	}

	schemaData, err := os.ReadFile("fixtures/client-migration-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Const any `json:"const"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Properties["contract"].Const != fixture.Contract {
		t.Fatal("schema and fixture contract differ")
	}
}
