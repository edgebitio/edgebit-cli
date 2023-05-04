package main

import (
	"context"
	"encoding/json"
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

func addUploadSBOMFlags(cmd *cobra.Command) {
	cmd.Flags().String("repo", "", "Source repository to tag the SBOM with")
	cmd.Flags().String("commit", "", "Source commit ID to tag the SBOM with")
	cmd.Flags().String("image-id", "", "Image ID to tag the SBOM with (required for most SBOM formats)")
	cmd.Flags().String("image-tag", "", "Image tag to tag the SBOM with")
	cmd.Flags().String("component", "", "Component name to associate the SBOM with")
	cmd.Flags().StringSlice("tag", nil, "EdgeBit Component tags to associate the SBOM with (can be specified multiple times)")
}

func parseUploadSBOMArgs(cmd *cobra.Command, args []string) (UploadSBOMArgs, error) {
	tags, err := cmd.Flags().GetStringSlice("tag")
	if err != nil {
		return UploadSBOMArgs{}, err
	}

	return UploadSBOMArgs{
		FileName:      args[0],
		Repo:          cmd.Flag("repo").Value.String(),
		Commit:        cmd.Flag("commit").Value.String(),
		ImageID:       cmd.Flag("image-id").Value.String(),
		ImageTag:      cmd.Flag("image-tag").Value.String(),
		ComponentName: cmd.Flag("component").Value.String(),
		Tags:          tags,
	}, nil
}

func uploadSBOMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload-sbom",
		Short: "Upload a Software Bill of Materials (SBOM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cli, err := NewCLI(ctx)
			if err != nil {
				return err
			}

			uploadArgs, err := parseUploadSBOMArgs(cmd, args)
			if err != nil {
				return err
			}

			sbomID, err := cli.uploadSBOM(ctx, uploadArgs)
			if err != nil {
				return err
			}

			fmt.Printf("Uploaded SBOM %s\n", sbomID)
			return nil
		},
		Args: cobra.ExactArgs(1),
	}

	addUploadSBOMFlags(cmd)

	return cmd
}

func uploadSBOMCommandForCI() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload-sbom-for-ci",
		Short: "Upload an SBOM and print machine-readable output for use in CI",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cli, err := NewCLI(ctx)
			if err != nil {
				return err
			}

			uploadArgs, err := parseUploadSBOMArgs(cmd, args)
			if err != nil {
				return err
			}

			out, err := cli.uploadSBOMForCI(ctx, UploadSBOMForCIArgs{
				UploadSBOMArgs: uploadArgs,
				BaseCommit:     cmd.Flag("base-commit").Value.String(),
				CommentFlavor:  cmd.Flag("comment-flavor").Value.String(),
			})
			if err != nil {
				return err
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			err = enc.Encode(out)
			if err != nil {
				return err
			}

			return nil
		},
		Args:   cobra.ExactArgs(1),
		Hidden: true,
	}

	addUploadSBOMFlags(cmd)

	cmd.Flags().String("base-commit", "", "Base commit ID to compare the SBOM against")
	cmd.Flags().String("comment-flavor", "", "Optional comment flavor to use for the SBOM (github)")

	return cmd
}

type CLI struct {
	// We'll need a proper interceptor here long term
	apiClient    platformv1alphaconnect.EdgeBitPublicAPIServiceClient
	sessionToken string
	ProjectID    string
}

func NewCLI(ctx context.Context) (*CLI, error) {
	apiKey := os.Getenv("EDGEBIT_API_KEY")
	if apiKey == "" {
		return nil, errors.New("EDGEBIT_API_KEY is required")
	}

	edgebitURL := os.Getenv("EDGEBIT_URL")
	if edgebitURL == "" {
		return nil, errors.New("EDGEBIT_URL is required")
	}

	loginClient := platformv1alphaconnect.NewLoginServiceClient(
		http.DefaultClient,
		edgebitURL,
	)

	loginResponse, err := loginClient.APIAccessTokenLogin(ctx, connect.NewRequest(&platform.APIAccessTokenLoginRequest{
		Token: apiKey,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	apiClient := platformv1alphaconnect.NewEdgeBitPublicAPIServiceClient(
		http.DefaultClient,
		edgebitURL,
	)

	return &CLI{
		apiClient:    apiClient,
		sessionToken: loginResponse.Msg.SessionToken,
		ProjectID:    loginResponse.Msg.ProjectId,
	}, nil
}

func (c *CLI) uploadSBOMRequest(ctx context.Context) *connect.ClientStreamForClient[platform.UploadSBOMRequest, platform.UploadSBOMResponse] {
	uploadRequest := c.apiClient.UploadSBOM(ctx)
	uploadRequest.RequestHeader().Set("Authorization", "Bearer "+c.sessionToken)

	return uploadRequest
}

type UploadSBOMArgs struct {
	FileName      string
	ImageID       string
	ImageTag      string
	Repo          string
	Commit        string
	ComponentName string
	Tags          []string
}

func (cli *CLI) uploadSBOM(ctx context.Context, args UploadSBOMArgs) (string, error) {
	sbomFile := args.FileName
	if sbomFile == "" {
		return "", errors.New("sbom file is required")
	}

	file, err := os.Open(sbomFile)
	if err != nil {
		return "", fmt.Errorf("failed to open '%s': %w", sbomFile, err)
	}

	sbom, format, err := formats.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode sbom: %w", err)
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
		return "", fmt.Errorf("unsupported SBOM format: %s", format.ID())
	}

	// If an image ID or tag was specified, use that. Otherwise, use whatever we were able to infer from the SBOM.
	if args.ImageID != "" {
		imageID = args.ImageID
	}
	if imageID == "" {
		return "", errors.New("image ID cannot be inferred from this SBOM format, specify it with --image-id")
	}

	if args.ImageTag != "" {
		imageTag = args.ImageTag
	}

	if len(args.Tags) > 0 && args.ComponentName == "" {
		return "", errors.New("component name is required when specifying tags")
	}

	uploadRequest := cli.uploadSBOMRequest(ctx)

	err = uploadRequest.Send(&platform.UploadSBOMRequest{
		Kind: &platform.UploadSBOMRequest_Header{
			Header: &platform.UploadSBOMHeader{
				ProjectId:      cli.ProjectID,
				Format:         uploadFormat,
				Labels:         map[string]string{},
				SourceRepoUrl:  args.Repo,
				SourceCommitId: args.Commit,
				ImageId:        imageID,
				Image: &platform.Image{
					Kind: &platform.Image_Docker{
						Docker: &platform.DockerImage{
							Tag: imageTag,
						},
					},
				},
				ComponentName: args.ComponentName,
				Tags:          args.Tags,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to send upload request: %w", err)
	}

	file, err = os.Open(sbomFile)
	if err != nil {
		return "", fmt.Errorf("failed to open '%s': %w", sbomFile, err)
	}

	chunk := make([]byte, 4*1024)

	for {
		size, err := file.Read(chunk)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return "", err
			}
		}

		err = uploadRequest.Send(&platform.UploadSBOMRequest{
			Kind: &platform.UploadSBOMRequest_Data{
				Data: chunk[:size],
			},
		})
		if err != nil {
			return "", err
		}
	}

	uploadResponse, err := uploadRequest.CloseAndReceive()
	if err != nil {
		return "", err
	}

	return uploadResponse.Msg.Id, nil
}

type UploadSBOMForCIArgs struct {
	UploadSBOMArgs
	CommentFlavor string
	BaseCommit    string
}

type UploadSBOMForCIOutput struct {
	CommentBody string `json:"comment_body"`
}

func (cli *CLI) uploadSBOMForCI(ctx context.Context, args UploadSBOMForCIArgs) (*UploadSBOMForCIOutput, error) {
	var commentFlavor platform.CIBotCommentFlavor

	switch args.CommentFlavor {
	case "":
		commentFlavor = platform.CIBotCommentFlavor_CI_BOT_COMMENT_FLAVOR_UNSPECIFIED
	case "github":
		commentFlavor = platform.CIBotCommentFlavor_CI_BOT_COMMENT_FLAVOR_GITHUB
	default:
		return nil, fmt.Errorf("unsupported comment flavor: %s", args.CommentFlavor)
	}

	if args.Commit == "" {
		return nil, errors.New("commit is required")
	}

	sbomID, err := cli.uploadSBOM(ctx, args.UploadSBOMArgs)
	if err != nil {
		return nil, err
	}

	req := connect.NewRequest(&platform.GetCIBotCommentRequest{
		ProjectId:    cli.ProjectID,
		SbomId:       sbomID,
		CommitId:     args.Commit,
		BaseCommitId: args.BaseCommit,
		Flavor:       commentFlavor,
	})
	req.Header().Add("Authorization", "Bearer "+cli.sessionToken)

	commentRes, err := cli.apiClient.GetCIBotComment(ctx, req)
	if err != nil {
		return nil, err
	}

	return &UploadSBOMForCIOutput{
		CommentBody: commentRes.Msg.CommentBody,
	}, nil
}
