package sboms

import (
	"context"
	"testing"

	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/stretchr/testify/require"
)

func TestLoadSBOM(t *testing.T) {
	tests := []struct {
		name        string
		image       string
		invalidSBOM bool
	}{
		{
			// Modern Ghost image with an SBOM attached in the Docker style.
			name:  "Ghost",
			image: "ghost:5.75.0-alpine",
		},
		{
			// Example from the Docker docs:
			// https://github.com/docker/buildx/blob/5b5c4c8c9df55e133c39cce8153e0fa9fc6f60c4/docs/reference/buildx_imagetools_inspect.md
			name:  "CrazyMaxBuildkit",
			image: "index.docker.io/crazymax/buildkit@sha256:7007b387ccd52bd42a050f2e8020e56e64622c9269bf7bbe257b326fe99daf19",
		},
		{
			// A random older (late 2022) Chainguard static base image with a .sbom
			// attached.
			name:        "ChainguardStaticOld",
			image:       "cgr.dev/chainguard/static@sha256:3d7a2b4e485b98ffc9a8dc10a7c8bc82bc235f72cf166abb8058e5a65648c500",
			invalidSBOM: true,
		},
		{
			// A newer (late 2023) Chainguard static base image with a .att attestation,
			// but not .sbom.
			name:  "ChainguardStaticModern",
			image: "cgr.dev/chainguard/static@sha256:606b571cf58a1f29a65ed4a09973b02664ce61a1325e8295f9ab1e38a1ac0632",
		},
		{
			// Unpinned Chainguard static base image.
			name:  "ChainguardLatest",
			image: "cgr.dev/chainguard/static",
		},
		{
			// Unpinned Distroless static base image.
			name:  "DistrolessStaticLatest",
			image: "gcr.io/distroless/static",
		},
		{
			// Unpinned rekor-server image.
			name:  "GCRRekor",
			image: "gcr.io/projectsigstore/rekor-server:v1.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			loader := NewDefaultRegistryLoader(ctx)

			data, err := loader.Load(ctx, tt.image)
			require.NoError(t, err)

			sbom, format, err := formats.Decode(data)
			if tt.invalidSBOM {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, format.ID(), spdxjson.ID)
			require.Greater(t, sbom.Artifacts.Packages.PackageCount(), 0)
		})
	}
}
