# @hypercyber/signer-client

TypeScript / Node.js gRPC client for the HyperCyber Vault signing service.

## Install

The package is published to **GitHub Packages** (private). Configure the registry once per project — drop an `.npmrc` next to your `package.json`:

```ini
@hypercyber:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

Then provide `NPM_TOKEN` (a PAT with `read:packages`, or the `GITHUB_TOKEN` in CI) and install:

```bash
npm install @hypercyber/signer-client
```

## Usage

```ts
import { VaultClient } from '@hypercyber/signer-client';

const c = new VaultClient('vault.example.com:8080', {
  secret: process.env.VAULT_SECRET,
  caCertFile: '/run/hypercyber-secrets/signer-server-ca.crt',
  clientCertFile: '/run/hypercyber-secrets/signer-task-client.crt',
  clientKeyFile: '/run/hypercyber-secrets/signer-task-client.key',
});

// Every wallet uses threshold ECDSA. No custody model to pick:
// the address is produced by distributed key generation and no node holds the key.
const wallet = await c.create('default', 'wallet-001');
// { walletId, ecdsaPubKey, attestations, groupPubkey, threshold, allIds, attested }

const signed = await c.signByWallet({
  requestId: 'req-001',
  walletId: 'wallet-001',
  network: 'ethereum',
  chainId: 1n,
  transaction: rlpEncodedTx,
});

c.close();
```

### Connection options

```ts
new VaultClient(endpoint, {
  secret,        // required for authenticated servers; sent as x-vault-secret metadata
  insecure,      // disable TLS (local dev only)
  caCertFile,    // path to a custom CA cert (e.g. self-signed)
  clientCertFile,// caller certificate; configure with clientKeyFile
  clientKeyFile, // caller private key; mutual TLS also requires secret
});
```

Secure channels require TLS 1.3. A client certificate must be paired with its
private key and a per-identity `secret`; it cannot be used with `insecure`.

If both `insecure` and `caCertFile` are omitted, TLS uses the system trust store.

### Verifying that a new wallet is really threshold-backed

`create` returns an address on the server's word alone. A compromised vault
frontend can skip the key-generation ceremony, generate a key it alone knows, and
hand back that address — you fund a wallet whose threshold never existed.

Each signer node therefore holds a long-term identity key and signs a statement
that it holds a share of the new wallet. Configure the matching public keys and
`create` **throws** unless enough distinct nodes signed:

```ts
import { VaultClient, parseNodeKeys } from '@hypercyber/signer-client';

const c = new VaultClient(endpoint, {
  secret,
  // partyId:compressedPubkeyHex — from `hypercyber-signer generate-node-key` on each signer,
  // delivered out of band. Never read these from a vault response: a client that
  // does is asking the vault whether the vault is honest.
  nodeKeys: parseNodeKeys(process.env.VAULT_NODE_PUBKEYS!),
  attestationThreshold: 2,
});

const wallet = await c.create('default', 'wallet-001'); // throws if unattested
```

Notes:

- Omitting `nodeKeys` keeps the previous behaviour and reports `attested: false`.
  That is correct for a single-host deployment, which has nothing independent to
  attest; on a distributed one it throws the guarantee away.
- Passing an **empty** `nodeKeys` array is an error, not a quiet fall back —
  asking for verification and silently not getting it is worse than not asking.
- `attestationThreshold` is yours, not the server's, and is never below 2.
  Letting the response decide how many attestations are enough would let a
  compromised one decide "one".
- One public key configured under two party ids is rejected at construction: that
  single node could otherwise sign twice and clear a 2-of-3 by itself.

`statementDigest`, `validateNodeKeys` and `verifyAttestations` are exported for
callers that persist attestations and re-check them later.

### Describing what you are signing

`typedDataWithAction` does the same for a Hyperliquid L1 action. Its
`actionMsgpack` must be the bytes the Hyperliquid SDK itself produced, not a
re-encoding: the vault checks that those exact bytes derive the hashes in the
same request, which is what makes the description binding rather than declared.

Notes:


## API

| Method | Description |
|--------|-------------|
| `create(markup, walletId)` | Create a threshold wallet via DKG → `{ walletId, ecdsaPubKey, attestations, groupPubkey, threshold, allIds, attested }`. Throws when `nodeKeys` is configured and the wallet is not attested |
| `signByAddress({ requestId, address, network, chainId, transaction })` | Sign by address → `Uint8Array` |
| `signByWallet({ requestId, walletId, network, chainId, transaction })` | Sign by wallet ID → `Uint8Array` |
| `typedData({ requestId, address, network, chainId, domainSeparator, typedDataHash })` | Sign EIP-712 from hashes alone → `{ r, s, v }`. Describes nothing; refused by a credential in enforce mode |
| `typedDataWithAction({ …typedData, action })` | Sign EIP-712 **with** the Hyperliquid L1 action → `{ r, s, v }` |
| `close()` | Close the gRPC channel |

### Type conventions

| Field | TypeScript type | Notes |
|-------|----------------|-------|
| `chainId` | `bigint` | Encoded as big-endian bytes on the wire |
| `address` | `string \| Uint8Array` | Hex string (with or without `0x`) or raw 20 bytes |
| `r`, `s` (response) | `bigint` | Big-endian bytes parsed back to `bigint` |
| `v` (response) | `number` | Recovery ID (27 or 28) |
| `transaction`, `domainSeparator`, `typedDataHash` | `Uint8Array` | Raw bytes |
| `action.nonce`, `action.expiresAfter` | `bigint \| number` | proto `uint64`, sent as a decimal string so values above 2^53 stay exact |

## Migrating from 0.5.x

0.6.0 removes the retired Paymaster-only typed message, Calibur batch, and
EIP-7702 SetCode methods. Hyperliquid callers continue to use
`typedDataWithAction`; transaction and wallet APIs are unchanged.

## Migrating from 0.4.x

0.5.0 adds `typedDataWithAction`, which is what a Hyperliquid vault credential
in `enforce` mode requires — see
[Describing what you are signing](#describing-what-you-are-signing).

## Migrating from 0.3.x

0.4.0 is additive. `create`'s result gains `attestations`, `groupPubkey`,
`threshold`, `allIds` and `attested`; existing fields and every signing method
are unchanged, and a client that passes no `nodeKeys` behaves exactly as before.

To start verifying, pass `nodeKeys` — see
[Verifying that a new wallet is really threshold-backed](#verifying-that-a-new-wallet-is-really-threshold-backed).

## Migrating from 0.2.x

0.3.0 removes the custody-version API. All wallets are now MPC + TSS.

- `Version`, `VERSION_LOCAL` and `VERSION_MPC` are gone. Delete the imports.
- `create(markup, walletId, version)` → `create(markup, walletId)`.
- `import(...)` is **removed**, along with the `Import` RPC and `ImportResult`.
  There is no replacement: threshold custody has no way to ingest a pre-existing
  private key. Callers still invoking it get `UNIMPLEMENTED` from gRPC.
- **Existing wallets keep their addresses.** The server-side `hypercyber-signer migrate`
  tool converts legacy single-key wallets in place, splitting each key into a
  threshold sharing for that same address. Nothing moves on-chain and no client
  change is needed — the same wallet id and the same address keep working.

Signing methods are unchanged in behaviour and signature.

## Releasing (maintainers)

1. Bump the `version` field in `package.json` (e.g. `0.1.1`).
2. Commit and tag with the Go-subdirectory convention: `client-ts/v0.1.1`.
3. Push the tag — the [`publish-client-ts`](../.github/workflows/publish-client-ts.yml) workflow publishes to GitHub Packages automatically.

```bash
git tag client-ts/v0.1.1
git push origin client-ts/v0.1.1
```

The workflow verifies that the tag version matches `package.json` before publishing.

## Development

```bash
npm install
npm run build         # tsc → dist/
npm test              # node:test over test/*.test.ts
npm run example       # ts-node examples/basic.ts (requires a running vault)
npm pack --dry-run    # preview the published tarball
```

`test/fixtures.json` is generated by the Go `attest` package
(`go run ./client-ts/test/gen-fixtures` from the repo root) and checked back
against it by `go test ./client-ts/...`. The attestation digest has to match Go's
byte for byte; two implementations written from the same description agree with
the description and not necessarily with each other, and a digest that differs by
one byte makes every genuine attestation look forged rather than failing loudly.
Never hand-edit the fixtures.

`proto/vault.proto` is a relative symlink to the canonical proto at [`../proto/vault/v1/vault.proto`](../proto/vault/v1/vault.proto). The `prepack` hook materializes the symlink into a real file so the proto is shipped inside the npm tarball; `postpack` restores the symlink afterwards.
