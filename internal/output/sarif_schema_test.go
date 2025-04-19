package output

import (
	"embed"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed sarif-2.1.0.json
var sarifSchema embed.FS

func TestSARIFSchemaValidation(t *testing.T) {
	// Load the schema
	schemaData, err := sarifSchema.ReadFile("sarif-2.1.0.json")
	require.NoError(t, err)

	compiler := jsonschema.NewCompiler()
	err = compiler.AddResource("sarif-2.1.0.json", schemaData)
	require.NoError(t, err)

	schema, err := compiler.Compile("sarif-2.1.0.json")
	require.NoError(t, err)

	// Create a test finding
	finding := Finding{
		RuleID:      "test-rule",
		Description: "Test finding",
		Severity:    "high",
		Path:        "test/file.txt",
		Line:        42,
		Match:       "sensitive data",
	}

	// Generate SARIF
	sarif, err := generateSARIF([]Finding{finding})
	require.NoError(t, err)

	// Marshal to JSON for validation
	sarifJSON, err := json.Marshal(sarif)
	require.NoError(t, err)

	// Validate against schema
	var v interface{}
	err = json.Unmarshal(sarifJSON, &v)
	require.NoError(t, err)

	err = schema.Validate(v)
	assert.NoError(t, err)
}
