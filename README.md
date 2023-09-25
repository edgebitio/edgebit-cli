# EdgeBit CLI - ebctl

The `ebctl` tool uploads software bill-of-materials (SBOM) and build metadata to EdgeBit for vulnerability analysis and dependency inventory. Read the [full documentation](https://edgebit.io/docs/0.x/install-build-generic/) for more details.

EdgeBit secures your software supply chain by focusing on code that is actually running. This simplifies vulnerability management as it cuts through noise, like inbox zero for CVEs.

Less noise equals less frustration between security and engineering teams. And faster software patching, of course. Sign up at https://signup.edgebit.io.

## Building & Running Tests

```console
cd cmd/ebctl
go build
```

## Releases

This project uses `goreleaser` triggered via a GitHub Action for any tag matching `v*`.