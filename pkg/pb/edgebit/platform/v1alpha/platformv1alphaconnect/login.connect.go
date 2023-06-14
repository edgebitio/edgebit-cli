// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: edgebit/platform/v1alpha/login.proto

package platformv1alphaconnect

import (
	context "context"
	errors "errors"
	connect_go "github.com/bufbuild/connect-go"
	v1alpha "github.com/edgebitio/edgebit-cli/pkg/pb/edgebit/platform/v1alpha"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect_go.IsAtLeastVersion0_1_0

const (
	// LoginServiceName is the fully-qualified name of the LoginService service.
	LoginServiceName = "edgebit.platform.v1alpha.LoginService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// LoginServicePasswordLoginProcedure is the fully-qualified name of the LoginService's
	// PasswordLogin RPC.
	LoginServicePasswordLoginProcedure = "/edgebit.platform.v1alpha.LoginService/PasswordLogin"
	// LoginServiceExchangeInviteTokenProcedure is the fully-qualified name of the LoginService's
	// ExchangeInviteToken RPC.
	LoginServiceExchangeInviteTokenProcedure = "/edgebit.platform.v1alpha.LoginService/ExchangeInviteToken"
	// LoginServiceAPIAccessTokenLoginProcedure is the fully-qualified name of the LoginService's
	// APIAccessTokenLogin RPC.
	LoginServiceAPIAccessTokenLoginProcedure = "/edgebit.platform.v1alpha.LoginService/APIAccessTokenLogin"
)

// LoginServiceClient is a client for the edgebit.platform.v1alpha.LoginService service.
type LoginServiceClient interface {
	PasswordLogin(context.Context, *connect_go.Request[v1alpha.PasswordLoginRequest]) (*connect_go.Response[v1alpha.PasswordLoginResponse], error)
	ExchangeInviteToken(context.Context, *connect_go.Request[v1alpha.ExchangeInviteTokenRequest]) (*connect_go.Response[v1alpha.ExchangeInviteTokenResponse], error)
	APIAccessTokenLogin(context.Context, *connect_go.Request[v1alpha.APIAccessTokenLoginRequest]) (*connect_go.Response[v1alpha.APIAccessTokenLoginResponse], error)
}

// NewLoginServiceClient constructs a client for the edgebit.platform.v1alpha.LoginService service.
// By default, it uses the Connect protocol with the binary Protobuf Codec, asks for gzipped
// responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the
// connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewLoginServiceClient(httpClient connect_go.HTTPClient, baseURL string, opts ...connect_go.ClientOption) LoginServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &loginServiceClient{
		passwordLogin: connect_go.NewClient[v1alpha.PasswordLoginRequest, v1alpha.PasswordLoginResponse](
			httpClient,
			baseURL+LoginServicePasswordLoginProcedure,
			opts...,
		),
		exchangeInviteToken: connect_go.NewClient[v1alpha.ExchangeInviteTokenRequest, v1alpha.ExchangeInviteTokenResponse](
			httpClient,
			baseURL+LoginServiceExchangeInviteTokenProcedure,
			opts...,
		),
		aPIAccessTokenLogin: connect_go.NewClient[v1alpha.APIAccessTokenLoginRequest, v1alpha.APIAccessTokenLoginResponse](
			httpClient,
			baseURL+LoginServiceAPIAccessTokenLoginProcedure,
			opts...,
		),
	}
}

// loginServiceClient implements LoginServiceClient.
type loginServiceClient struct {
	passwordLogin       *connect_go.Client[v1alpha.PasswordLoginRequest, v1alpha.PasswordLoginResponse]
	exchangeInviteToken *connect_go.Client[v1alpha.ExchangeInviteTokenRequest, v1alpha.ExchangeInviteTokenResponse]
	aPIAccessTokenLogin *connect_go.Client[v1alpha.APIAccessTokenLoginRequest, v1alpha.APIAccessTokenLoginResponse]
}

// PasswordLogin calls edgebit.platform.v1alpha.LoginService.PasswordLogin.
func (c *loginServiceClient) PasswordLogin(ctx context.Context, req *connect_go.Request[v1alpha.PasswordLoginRequest]) (*connect_go.Response[v1alpha.PasswordLoginResponse], error) {
	return c.passwordLogin.CallUnary(ctx, req)
}

// ExchangeInviteToken calls edgebit.platform.v1alpha.LoginService.ExchangeInviteToken.
func (c *loginServiceClient) ExchangeInviteToken(ctx context.Context, req *connect_go.Request[v1alpha.ExchangeInviteTokenRequest]) (*connect_go.Response[v1alpha.ExchangeInviteTokenResponse], error) {
	return c.exchangeInviteToken.CallUnary(ctx, req)
}

// APIAccessTokenLogin calls edgebit.platform.v1alpha.LoginService.APIAccessTokenLogin.
func (c *loginServiceClient) APIAccessTokenLogin(ctx context.Context, req *connect_go.Request[v1alpha.APIAccessTokenLoginRequest]) (*connect_go.Response[v1alpha.APIAccessTokenLoginResponse], error) {
	return c.aPIAccessTokenLogin.CallUnary(ctx, req)
}

// LoginServiceHandler is an implementation of the edgebit.platform.v1alpha.LoginService service.
type LoginServiceHandler interface {
	PasswordLogin(context.Context, *connect_go.Request[v1alpha.PasswordLoginRequest]) (*connect_go.Response[v1alpha.PasswordLoginResponse], error)
	ExchangeInviteToken(context.Context, *connect_go.Request[v1alpha.ExchangeInviteTokenRequest]) (*connect_go.Response[v1alpha.ExchangeInviteTokenResponse], error)
	APIAccessTokenLogin(context.Context, *connect_go.Request[v1alpha.APIAccessTokenLoginRequest]) (*connect_go.Response[v1alpha.APIAccessTokenLoginResponse], error)
}

// NewLoginServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewLoginServiceHandler(svc LoginServiceHandler, opts ...connect_go.HandlerOption) (string, http.Handler) {
	mux := http.NewServeMux()
	mux.Handle(LoginServicePasswordLoginProcedure, connect_go.NewUnaryHandler(
		LoginServicePasswordLoginProcedure,
		svc.PasswordLogin,
		opts...,
	))
	mux.Handle(LoginServiceExchangeInviteTokenProcedure, connect_go.NewUnaryHandler(
		LoginServiceExchangeInviteTokenProcedure,
		svc.ExchangeInviteToken,
		opts...,
	))
	mux.Handle(LoginServiceAPIAccessTokenLoginProcedure, connect_go.NewUnaryHandler(
		LoginServiceAPIAccessTokenLoginProcedure,
		svc.APIAccessTokenLogin,
		opts...,
	))
	return "/edgebit.platform.v1alpha.LoginService/", mux
}

// UnimplementedLoginServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedLoginServiceHandler struct{}

func (UnimplementedLoginServiceHandler) PasswordLogin(context.Context, *connect_go.Request[v1alpha.PasswordLoginRequest]) (*connect_go.Response[v1alpha.PasswordLoginResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("edgebit.platform.v1alpha.LoginService.PasswordLogin is not implemented"))
}

func (UnimplementedLoginServiceHandler) ExchangeInviteToken(context.Context, *connect_go.Request[v1alpha.ExchangeInviteTokenRequest]) (*connect_go.Response[v1alpha.ExchangeInviteTokenResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("edgebit.platform.v1alpha.LoginService.ExchangeInviteToken is not implemented"))
}

func (UnimplementedLoginServiceHandler) APIAccessTokenLogin(context.Context, *connect_go.Request[v1alpha.APIAccessTokenLoginRequest]) (*connect_go.Response[v1alpha.APIAccessTokenLoginResponse], error) {
	return nil, connect_go.NewError(connect_go.CodeUnimplemented, errors.New("edgebit.platform.v1alpha.LoginService.APIAccessTokenLogin is not implemented"))
}
