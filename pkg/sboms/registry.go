package sboms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var (
	ErrNoSBOM          = fmt.Errorf("no SBOM found")
	ErrSubjectMismatch = fmt.Errorf("subject mismatch")
)

type RegistryLoader struct {
	RegistryOpts []remote.Option
	Platform     v1.Platform
}

type RegistryLoaderArgs struct {
	Platform string
}

func NewDefaultRegistryLoader(ctx context.Context, args RegistryLoaderArgs) (*RegistryLoader, error) {
	platform, err := v1.ParsePlatform(args.Platform)
	if err != nil {
		return nil, err
	}

	return &RegistryLoader{
		RegistryOpts: []remote.Option{
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithContext(ctx),
		},
		Platform: *platform,
	}, nil
}

// extractDockerStyleSBOM extracts an SBOM stored in a Docker-style attestation.
//
// We treat ref as pointing to an Index, and look for a manifest in that Index where the
// "vnd.docker.reference.type" annotation is "attestation-manifest" and the
// "vnd.docker.reference.digest" annotation is the digest of the target image.
//
// This is based on https://docs.docker.com/build/attestations/attestation-storage/
func (r *RegistryLoader) loadDockerStyleSBOM(ctx context.Context, desc *remote.Descriptor, targetImage v1.Image) (io.ReadCloser, error) {
	resolvedImageDigest, err := targetImage.Digest()
	if err != nil {
		return nil, err
	}

	index, err := desc.ImageIndex()
	if err != nil {
		return nil, ErrNoSBOM
	}

	idxManifest, err := index.IndexManifest()
	if err != nil {
		return nil, ErrNoSBOM
	}

	// Search the Index for an attestation manifest pointing to the target image.
	for _, desc := range idxManifest.Manifests {
		if desc.Annotations["vnd.docker.reference.type"] != "attestation-manifest" {
			continue
		}

		if desc.Annotations["vnd.docker.reference.digest"] != resolvedImageDigest.String() {
			continue
		}

		image, err := index.Image(desc.Digest)
		if err != nil {
			return nil, err
		}

		// Found a match, return the SBOM contained in the image this manifest points to.
		return r.loadSBOMFromImage(ctx, image, resolvedImageDigest)
	}

	return nil, ErrNoSBOM
}

// loadCosignLegacySBOM attempts to load an SBOM stored in the legacy Cosign format.
//
// Specifically, we search for an SBOM stored directly in a layer in an image tagged
// 'sha256-{targetImageDigest}.sbom'.
//
// See: https://github.com/sigstore/cosign/blob/main/specs/SBOM_SPEC.md
func (r *RegistryLoader) loadCosignLegacySBOM(ctx context.Context, ref name.Reference, targetImage v1.Image) (io.ReadCloser, error) {
	subject, err := targetImage.Digest()
	if err != nil {
		return nil, err
	}

	sbomRef, err := buildOCIRef(ref.Context(), subject, "sbom")
	if err != nil {
		return nil, err
	}

	image, err := remote.Image(sbomRef, r.RegistryOpts...)
	if err != nil {
		return nil, ErrNoSBOM
	}

	return r.loadSBOMFromImage(ctx, image, subject)
}

// loadCosignAttestationSBOM attempts to load an SBOM stored in the modern Cosign format.
//
// Specifically, we load a manifest tagged 'sha256-{targetImageDigest}.att', and look for
// an SBOM stored in an in-toto Statement wrapped in a DSSE envelope which is stuck into
// a layer in the image.
//
// In practice, these .att images seem to frequently contain dozens of layers containing
// similar DSSE envelopes which apply to some other image, so it is critical to search
// through them to find a Statement which identifies the target image as its Subject.
//
// See: https://github.com/sigstore/cosign/blob/main/specs/ATTESTATION_SPEC.md
func (r *RegistryLoader) loadCosignAttestationSBOM(ctx context.Context, ref name.Reference, targetImage v1.Image) (io.ReadCloser, error) {
	subject, err := targetImage.Digest()
	if err != nil {
		return nil, err
	}

	attestationRef, err := buildOCIRef(ref.Context(), subject, "att")
	if err != nil {
		return nil, err
	}

	image, err := remote.Image(attestationRef, r.RegistryOpts...)
	if err != nil {
		return nil, ErrNoSBOM
	}

	return r.loadSBOMFromImage(ctx, image, subject)
}

// loadSBOMFromImage searches the given image for an SBOM stored in a layer referencing
// the indicated subject.
//
// This method is common to all SBOM storage formats we support, and attempts (somewhat)
// to be generically capable of handling any future formats we may encounter.
func (r *RegistryLoader) loadSBOMFromImage(ctx context.Context, image v1.Image, subject v1.Hash) (io.ReadCloser, error) {
	manifest, err := image.Manifest()
	if err != nil {
		return nil, err
	}

	for _, desc := range manifest.Layers {
		switch {
		// Handle SBOMs stored directly in a layer. Nothing about how we handle these is
		// format-specific, so the above test can be extended in the future to support any
		// other media type we encounter.
		//
		// In practice this seems to correspond exclusively to the legacy Cosign SBOM storage
		// format.
		case desc.MediaType == "spdx+json" || desc.MediaType == "text/spdx+json":

			layer, err := image.LayerByDigest(desc.Digest)
			if err != nil {
				return nil, err
			}

			return layer.Uncompressed()

		// Handle SBOMs stored within an in-toto Statement.
		//
		// This is the format used by Docker for SBOM storage. This could be extended
		// in the storage to support other SBOM predicate types, eg CycloneDX:
		// https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md
		case desc.MediaType == "application/vnd.in-toto+json" &&
			desc.Annotations["in-toto.io/predicate-type"] == "https://spdx.dev/Document":
			layer, err := image.LayerByDigest(desc.Digest)
			if err != nil {
				return nil, err
			}

			sbom, err := r.extractSBOMFromStatementLayer(ctx, layer, subject)
			if err != nil {
				if err == ErrSubjectMismatch {
					continue
				} else {
					return nil, err
				}
			}

			return sbom, nil

		// Handle SBOMs stored in an in-toto Statement wrapped in a DSSE envelope.
		//
		// Again, this could be extended to support other JSON formatted SBOMs such
		// as CycloneDX:
		// https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md
		case desc.MediaType == "application/vnd.dsse.envelope.v1+json" &&
			desc.Annotations["predicateType"] == "https://spdx.dev/Document":
			layer, err := image.LayerByDigest(desc.Digest)
			if err != nil {
				return nil, err
			}

			sbom, err := r.extractSBOMFromEnvelopeLayer(ctx, layer, subject)
			if err != nil {
				if err == ErrSubjectMismatch {
					continue
				} else {
					return nil, err
				}
			}

			return sbom, nil
		}
	}

	return nil, fmt.Errorf("unable to find supported SBOM layer within image")
}

// extractSBOMFromEnvelopeLayer extracts an SBOM from a layer containing a DSSE envelope
// wrapping an in-toto Statement.
//
// If the Statement does not identify the given subject as its Subject, ErrSubjectMismatch
// is returned.
func (r *RegistryLoader) extractSBOMFromEnvelopeLayer(ctx context.Context, layer v1.Layer, subject v1.Hash) (io.ReadCloser, error) {
	data, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}

	defer data.Close()

	envelope := &dsseEnvelope{}

	err = json.NewDecoder(data).Decode(envelope)
	if err != nil {
		return nil, fmt.Errorf("error decoding DSSE envelope: %w", err)
	}

	statement, err := envelope.UnmarshalStatement()
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling DSSE statement: %w", err)
	}

	if !statement.AppliesTo(subject) {
		return nil, ErrSubjectMismatch
	}

	// It seems like some implementations (e.g. gcr.io/distroless/static) store the SBOM
	// as a JSON string in the predicate field, rather than a JSON object.
	//
	// As a special case, we'll try to decode the predicate and return the underlying
	// JSON.
	if len(statement.Predicate) > 0 && statement.Predicate[0] == '"' {
		var predicateJSON string

		err := json.Unmarshal(statement.Predicate, &predicateJSON)
		if err != nil {
			return nil, fmt.Errorf("error decoding predicate JSON string: %w", err)
		}

		return io.NopCloser(bytes.NewReader([]byte(predicateJSON))), nil
	}

	return io.NopCloser(bytes.NewReader(statement.Predicate)), nil
}

// extractSBOMFromStatementLayer extracts an SBOM from a layer containing an in-toto
// Statement.
//
// If the Statement does not identify the given subject as its Subject, ErrSubjectMismatch
// is returned.
func (r *RegistryLoader) extractSBOMFromStatementLayer(ctx context.Context, layer v1.Layer, subject v1.Hash) (io.ReadCloser, error) {
	data, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}

	defer data.Close()

	statement := &inTotoStatement{}

	err = json.NewDecoder(data).Decode(statement)
	if err != nil {
		return nil, fmt.Errorf("error decoding attestation Statement: %w", err)
	}

	if !statement.AppliesTo(subject) {
		return nil, ErrSubjectMismatch
	}

	return io.NopCloser(bytes.NewReader(statement.Predicate)), nil
}

// resolveImage attempts to resolve the given descriptor to a target image
// based on the RegistryLoader's configured platform. If no platform is configured
// this will fail when attempting to resolve a multi-platform index.
func (r *RegistryLoader) resolveImage(ctx context.Context, desc *remote.Descriptor) (v1.Image, error) {
	// If the descriptor is already an image, just return it.
	if desc.MediaType.IsImage() {
		return desc.Image()
	}

	index, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}

	indexManifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}

	runnableImages := []v1.Descriptor{}

	// Iterate through the index's manifests to try to make a list of "runnable" images
	// (ie not "attestation-manifest" images, etc).
	for _, desc := range indexManifest.Manifests {
		if !desc.MediaType.IsImage() {
			continue
		}

		if desc.Platform == nil || desc.Platform.Architecture == "" || desc.Platform.Architecture == "unknown" {
			continue
		}

		// r.Platform is treated here as a set of "requirements", meaning fields which are
		// not set are not used for filtering. So if r.Platform is parsed from an empty
		// string, all images matching the criteria above will be considered runnable.
		if desc.Platform.Satisfies(r.Platform) {
			runnableImages = append(runnableImages, *desc.DeepCopy())
		}
	}

	if len(runnableImages) == 0 {
		return nil, fmt.Errorf("no runnable images match platform: %s", r.Platform.String())
	} else if len(runnableImages) > 1 {
		platforms := []string{}
		for _, desc := range runnableImages {
			platforms = append(platforms, desc.Platform.String())
		}

		return nil, fmt.Errorf("found multiple matching images in index: %s", strings.Join(platforms, ", "))
	}

	return index.Image(runnableImages[0].Digest)
}

// Load attempts to locate an SBOM for the given image reference, and returns an
// io.ReadCloser which can be used to read the raw bytes of the SBOM.
func (r *RegistryLoader) Load(ctx context.Context, refStr string) (io.ReadCloser, error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, err
	}

	// Fetch the referenced manifest so we can get the target image.
	desc, err := remote.Get(ref, r.RegistryOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading '%s': %w'", refStr, err)
	}

	// Resolve the referenced manifest to a target image.
	targetImage, err := r.resolveImage(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("error resolving '%s' to image: %w", refStr, err)
	}

	// Attempt to load a Docker-style SBOM.
	data, err := r.loadDockerStyleSBOM(ctx, desc, targetImage)
	if err != nil && err != ErrNoSBOM {
		return nil, err
	} else if err == nil {
		return data, nil
	}

	// Attempt to load a legacy Cosign-style SBOM.
	data, err = r.loadCosignLegacySBOM(ctx, ref, targetImage)
	if err != nil && err != ErrNoSBOM {
		return nil, err
	} else if err == nil {
		return data, nil
	}

	// Attempt to load a modern Cosign-style SBOM.
	data, err = r.loadCosignAttestationSBOM(ctx, ref, targetImage)
	if err != nil && err != ErrNoSBOM {
		return nil, err
	} else if err == nil {
		return data, nil
	}

	return nil, ErrNoSBOM
}

func buildOCIRef(base name.Repository, subject v1.Hash, ext string) (name.Reference, error) {
	return base.Tag(fmt.Sprintf("%s-%s.%s", subject.Algorithm, subject.Hex, ext)), nil
}
