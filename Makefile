generate:
	git submodule update --init
	go run github.com/bufbuild/buf/cmd/buf generate platform/proto/edgebit/platform/v1alpha/login.proto
	go run github.com/bufbuild/buf/cmd/buf generate platform/proto/edgebit/platform/v1alpha/platform.proto
