package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	platform "github.com/edgebitio/edgebit-cli/pkg/pb/edgebit/platform/v1alpha"
	"github.com/edgebitio/edgebit-cli/pkg/pb/edgebit/platform/v1alpha/platformv1alphaconnect"

	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/bufbuild/connect-go"
	"github.com/spf13/cobra"
)

func uploadSBOMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload-sbom",
		Short: "Upload a Software Bill of Materials (SBOM)",
		RunE:  uploadSBOM,
		Args:  cobra.ExactArgs(1),
	}

	cmd.Flags().String("repo", "", "Source repository to tag the SBOM with")
	cmd.Flags().String("commit", "", "Source commit ID to tag the SBOM with")
	cmd.Flags().String("image-id", "", "Image ID to tag the SBOM with (required for most SBOM formats)")
	cmd.Flags().String("image-tag", "", "Image tag to tag the SBOM with")

	return cmd
}

func uploadSBOM(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	apiKey := os.Getenv("EDGEBIT_API_KEY")
	if apiKey == "" {
		return errors.New("EDGEBIT_API_KEY is required")
	}

	edgebitURL := os.Getenv("EDGEBIT_URL")
	if edgebitURL == "" {
		return errors.New("EDGEBIT_URL is required")
	}

	sbomFile := args[0]
	if sbomFile == "" {
		return errors.New("sbom file is required")
	}

	file, err := os.Open(sbomFile)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", sbomFile, err)
	}

	sbom, format, err := formats.Decode(file)
	if err != nil {
		return fmt.Errorf("failed to decode sbom: %w", err)
	}

	file.Close()

	var imageID string
	var imageTag string

	var uploadFormat platform.SBOMFormat

	switch format.ID() {
	case syftjson.ID:
		imageID = sbom.Source.ImageMetadata.ID
		if len(sbom.Source.ImageMetadata.Tags) > 0 {
			imageTag = sbom.Source.ImageMetadata.Tags[0]
		}

		uploadFormat = platform.SBOMFormat_SBOM_FORMAT_SYFT

	case spdxjson.ID:
		uploadFormat = platform.SBOMFormat_SBOM_FORMAT_SPDX_JSON

	default:
		return fmt.Errorf("unsupported SBOM format: %s", format.ID())
	}

	if cmd.Flag("image-id").Changed {
		imageID = cmd.Flag("image-id").Value.String()
	}
	if imageID == "" {
		return errors.New("image ID cannot be inferred from this SBOM format, specify it with --image-id")
	}

	if cmd.Flag("image-tag").Changed {
		imageTag = cmd.Flag("image-tag").Value.String()
	}

	repository := cmd.Flag("repo").Value.String()
	commit := cmd.Flag("commit").Value.String()

	loginClient := platformv1alphaconnect.NewLoginServiceClient(
		http.DefaultClient,
		edgebitURL,
	)

	loginResponse, err := loginClient.APIAccessTokenLogin(ctx, connect.NewRequest(&platform.APIAccessTokenLoginRequest{
		Token: apiKey,
	}))
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	apiClient := platformv1alphaconnect.NewEdgeBitPublicAPIServiceClient(
		http.DefaultClient,
		edgebitURL,
	)

	uploadRequest := apiClient.UploadSBOM(ctx)
	uploadRequest.RequestHeader().Set("Authorization", "Bearer "+loginResponse.Msg.SessionToken)

	err = uploadRequest.Send(&platform.UploadSBOMRequest{
		Kind: &platform.UploadSBOMRequest_Header{
			Header: &platform.UploadSBOMHeader{
				ProjectId:      loginResponse.Msg.ProjectId,
				Format:         uploadFormat,
				Labels:         map[string]string{},
				SourceRepoUrl:  repository,
				SourceCommitId: commit,
				ImageId:        imageID,
				Image: &platform.Image{
					Kind: &platform.Image_Docker{
						Docker: &platform.DockerImage{
							Tag: imageTag,
						},
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send upload request: %w", err)
	}

	file, err = os.Open(sbomFile)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", sbomFile, err)
	}

	chunk := make([]byte, 4*1024)

	for {
		size, err := file.Read(chunk)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return err
			}
		}

		err = uploadRequest.Send(&platform.UploadSBOMRequest{
			Kind: &platform.UploadSBOMRequest_Data{
				Data: chunk[:size],
			},
		})
		if err != nil {
			return err
		}
	}

	uploadResponse, err := uploadRequest.CloseAndReceive()
	if err != nil {
		return err
	}

	fmt.Printf("Uploaded SBOM %s\n", uploadResponse.Msg.Id)

	return nil
}
