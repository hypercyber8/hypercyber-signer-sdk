# HyperCyber Signer SDK

Client SDKs and the public gRPC contract for the HyperCyber threshold-signing
service.

## Packages

- `client`: Go gRPC client.
- `attest`: client-side verification for threshold-wallet attestations.
- `proto/vault/v1`: client-facing Vault API contract and generated Go types.
- `client-ts`: TypeScript gRPC client.

## Security boundary

This repository contains only the information a client needs to call and verify
the signing service. It deliberately excludes signer-node internals, including
MPC round protocols, key shares, storage, KMS integration, server-side policy,
audit storage, migration, and deployment configuration.

The SDK never receives or stores a wallet private key. Signing requests are sent
to the Vault service over gRPC and the returned signatures are verified or used
by the caller.

## Go

```go
import vaultclient "github.com/hypercyber8/hypercyber-signer-sdk/client"
```

Production callers should use one certificate/key pair and one secret per
least-privilege identity:

```go
client, err := vaultclient.New(ctx, endpoint,
    vaultclient.WithCACert("/run/hypercyber-secrets/signer-server-ca.crt"),
    vaultclient.WithClientCertificate(
        "/run/hypercyber-secrets/signer-task-funding-client.crt",
        "/run/hypercyber-secrets/signer-task-funding-client.key",
    ),
    vaultclient.WithSecret(secret),
)
```

The client certificate and `x-vault-secret` are two required factors when the
server enables enforcement. TLS clients require TLS 1.3. Do not share either
identity across callers.

`Create` is idempotent for the same `(walletID, markup)`. Use `GetWallet` to
resolve an existing wallet's public identity.

```bash
go test ./...
```

## TypeScript

See [`client-ts/README.md`](client-ts/README.md).
