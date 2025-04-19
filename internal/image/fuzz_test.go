//go:build fuzz
// +build fuzz

package image

import (
	"encoding/json"
	"testing"

	"github.com/opencontainers/image-spec/specs-go/v1"
)

func FuzzDiffLayers(f *testing.F) {
	// Add seed corpora
	seeds := []struct {
		name     string
		manifest v1.Manifest
	}{
		{
			name: "empty_manifest",
			manifest: v1.Manifest{
				Versioned: specs.Versioned{
					SchemaVersion: 2,
				},
				Config: v1.Descriptor{
					MediaType: v1.MediaTypeImageConfig,
					Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
					Size:      7023,
				},
				Layers: []v1.Descriptor{},
			},
		},
		{
			name: "single_layer",
			manifest: v1.Manifest{
				Versioned: specs.Versioned{
					SchemaVersion: 2,
				},
				Config: v1.Descriptor{
					MediaType: v1.MediaTypeImageConfig,
					Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
					Size:      7023,
				},
				Layers: []v1.Descriptor{
					{
						MediaType: v1.MediaTypeImageLayer,
						Digest:    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
						Size:      32554,
					},
				},
			},
		},
	}

	for _, seed := range seeds {
		data, err := json.Marshal(seed.manifest)
		if err != nil {
			f.Fatalf("failed to marshal seed manifest: %v", err)
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var manifest v1.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			// Invalid JSON, skip this test case
			return
		}

		// Try to diff layers
		diffs, err := diffLayers(&manifest, &manifest)
		if err != nil {
			// We expect some errors from invalid manifests, but we want to catch
			// panics and other unexpected errors
			return
		}

		// Basic validation of results
		for _, diff := range diffs {
			if diff.Digest == "" {
				t.Error("empty digest in diff")
			}
			if diff.Size < 0 {
				t.Errorf("negative size in diff: %d", diff.Size)
			}
		}
	})
}
