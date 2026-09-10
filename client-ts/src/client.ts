import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';
import * as fs from 'fs';

import { type Attestation, type NodeKey, validateNodeKeys, verifyAttestations } from './attest';

export interface WalletCreateResult {
  walletId: string;
  ecdsaPubKey: string;
  /**
   * One entry per signer node that proved it holds a share of this wallet.
   * Empty on a single-host deployment, where there is nothing independent to
   * attest.
   */
  attestations: Attestation[];
  /** The 33-byte compressed group key. Part of what the attestations commit to. */
  groupPubkey: Uint8Array;
  /** The threshold the server says this wallet was created with. */
  threshold: number;
  /** The party ids the server says hold shares. */
  allIds: number[];
  /**
   * Whether at least `threshold` distinct signer nodes PROVED they hold a share.
   *
   * This is only ever true when `nodeKeys` was configured — without them there
   * is nothing to check the attestations against, and create() returns the
   * frontend's unverified word. When they ARE configured, an unattested wallet
   * never reaches the caller at all: create() throws. So this is a fact to log,
   * not a condition to branch on.
   */
  attested: boolean;
}

export interface Wallet {
  walletId: string;
  markup: string;
  address: string;
  groupPubkey: Uint8Array;
  threshold: number;
  allIds: number[];
}

export interface RSVResult {
  r: bigint;
  s: bigint;
  v: number;
}

export interface ClientOptions {
  /** Shared auth secret sent as the `x-vault-secret` metadata header. */
  secret?: string;
  /** Disable TLS. Local development only. */
  insecure?: boolean;
  /** Path to a CA certificate file (PEM) for self-signed servers. */
  caCertFile?: string;
  /** Override the bundled vault.proto path (rarely needed). */
  protoPath?: string;
  /**
   * Signer node identity public keys, which enable attestation verification and
   * make create() FAIL when a new wallet is not backed by
   * `attestationThreshold` distinct nodes.
   *
   * They must be learned out of band — from the operator, from this process's
   * own configuration, from anywhere other than the vault being checked. A
   * client that took them from the same response it is verifying would be asking
   * the vault whether the vault is honest.
   *
   * Leaving this unset keeps create() working and reports attested=false. That
   * is the deliberate default for a single-host deployment, which has nothing
   * independent to attest; on a distributed one, not setting it throws the
   * guarantee away.
   *
   * Passing an EMPTY array is an error rather than a quiet fall back to the
   * unverified default. Silently disabling verification for a caller that asked
   * for it is the worst outcome available: not asking leaves you knowing you are
   * trusting the frontend, while asking and getting nothing leaves you certain
   * of a guarantee you do not have.
   */
  nodeKeys?: NodeKey[];
  /**
   * How many distinct nodes must attest. Defaults to 2, and is never allowed
   * below it: letting the server choose how many attestations are enough would
   * let a compromised one choose "one".
   */
  attestationThreshold?: number;
}

export interface SignArgs {
  requestId: string;
  address: string;
  network: string;
  chainId: bigint;
  transaction: Uint8Array;
}

export interface SignByWalletArgs {
  requestId: string;
  walletId: string;
  network: string;
  chainId: bigint;
  transaction: Uint8Array;
}

export interface TypedDataArgs {
  requestId: string;
  address: string | Uint8Array;
  network: string;
  chainId: bigint;
  domainSeparator: Uint8Array;
  typedDataHash: Uint8Array;
}

/**
 * A Hyperliquid L1 action, so the vault can authorize WHAT is being signed
 * rather than only sign its hash.
 *
 * `actionMsgpack` must be the bytes the Hyperliquid SDK itself produced, not a
 * re-encoding. The vault checks that these exact bytes derive the
 * `domainSeparator` and `typedDataHash` in the same request, so the description
 * and the signature pre-image are the same thing and a caller cannot describe
 * one action while another gets signed. Bytes from a different encoder would
 * fail that check, and would in any case not match the body the SDK sends, which
 * the exchange would reject.
 */
export interface HyperliquidAction {
  /** The caller's own msgpack encoding of the action object. */
  actionMsgpack: Uint8Array;
  /** Appended big-endian when computing the action hash. */
  nonce: bigint | number;
  /** The sub-account this acts on behalf of, or omitted. */
  vaultAddress?: string;
  /**
   * Optional expiry. Omitting it and passing 0 produce DIFFERENT action hashes,
   * so this is `undefined` rather than 0 when there is none.
   */
  expiresAfter?: bigint | number;
  /**
   * Selects the phantom agent source tag. It does NOT change the domain: the L1
   * domain's chainId is 1337 on both networks.
   */
  isMainnet: boolean;
}

export interface TypedDataWithActionArgs extends TypedDataArgs {
  action: HyperliquidAction;
}

function bigIntToBytes(n: bigint, what = 'chainId'): Buffer {
	if (n < 0n) throw new Error(`${what} must be non-negative`);
	if (n >= 1n << 256n) throw new Error(`${what} does not fit uint256`);
  if (n === 0n) return Buffer.alloc(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

function bytesToBigInt(buf: Uint8Array | Buffer | undefined | null): bigint {
  if (!buf || buf.length === 0) return 0n;
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return BigInt('0x' + b.toString('hex'));
}

function hexToBytes(hex: string): Buffer {
  let s = hex.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
  if (s.length % 2) s = '0' + s;
  return Buffer.from(s, 'hex');
}

function addressToBytes(addr: string | Uint8Array): Buffer {
  if (typeof addr === 'string') return hexToBytes(addr);
  return Buffer.from(addr);
}

/** proto uint64. A string keeps values above 2^53 exact; a number does not. */
function uint64ToWire(n: bigint | number): string {
  const v = typeof n === 'number' ? BigInt(n) : n;
  if (v < 0n || v >= 1n << 64n) throw new Error(`value ${v} does not fit a uint64`);
  return v.toString(10);
}

function actionToWire(action: HyperliquidAction): Record<string, unknown> {
  const out: Record<string, unknown> = {
    actionMsgpack: Buffer.from(action.actionMsgpack),
    nonce: uint64ToWire(action.nonce),
    vaultAddress: action.vaultAddress ?? '',
    isMainnet: action.isMainnet,
  };
  // 0 and "absent" derive different action hashes, so the flag is what
  // distinguishes them — a bare 0 would silently describe a different action.
  if (action.expiresAfter !== undefined) {
    out.expiresAfter = uint64ToWire(action.expiresAfter);
    out.hasExpiresAfter = true;
  }
  return out;
}

interface VaultGrpcClient extends grpc.Client {
  Create(req: unknown, meta: grpc.Metadata, cb: (err: grpc.ServiceError | null, resp: any) => void): void;
  GetWallet(req: unknown, meta: grpc.Metadata, cb: (err: grpc.ServiceError | null, resp: any) => void): void;
  SignByAddress(req: unknown, meta: grpc.Metadata, cb: (err: grpc.ServiceError | null, resp: any) => void): void;
  SignByWallet(req: unknown, meta: grpc.Metadata, cb: (err: grpc.ServiceError | null, resp: any) => void): void;
  TypedData(req: unknown, meta: grpc.Metadata, cb: (err: grpc.ServiceError | null, resp: any) => void): void;
}

function loadService(protoPath: string): grpc.ServiceClientConstructor {
  if (!fs.existsSync(protoPath)) {
    throw new Error(`vault.proto not found at ${protoPath}`);
  }
  const def = protoLoader.loadSync(protoPath, {
    keepCase: false,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
    bytes: Buffer,
  });
  const pkg = grpc.loadPackageDefinition(def) as any;
  const ctor = pkg?.vault?.v1?.VaultService;
  if (!ctor) {
    throw new Error('VaultService not found in vault.proto package vault.v1');
  }
  return ctor;
}

export class VaultClient {
  private grpcClient: VaultGrpcClient;
  private secret?: string;
  private nodeKeys?: NodeKey[];
  private attestationThreshold: number;

  constructor(endpoint: string, opts: ClientOptions = {}) {
    const protoPath = opts.protoPath ?? path.join(__dirname, '..', 'proto', 'vault.proto');
    const ServiceCtor = loadService(protoPath);

    if (opts.nodeKeys !== undefined) {
      if (opts.nodeKeys.length === 0) {
        throw new Error(
          'VaultClient: nodeKeys was given no keys, which would disable the ' +
            'attestation verification it was passed to enable',
        );
      }
      // Check the configured identities here rather than only on the first
      // create(): a set that cannot carry a threshold — duplicate party ids, or
      // one key under two ids so a single node counts twice — is a deployment
      // mistake, and it should stop the process that made it instead of
      // surfacing the day someone creates a wallet.
      validateNodeKeys(opts.nodeKeys);
      this.nodeKeys = opts.nodeKeys;
    }
    this.attestationThreshold = Math.max(2, opts.attestationThreshold ?? 2);

    let creds: grpc.ChannelCredentials;
    if (opts.insecure) {
      creds = grpc.credentials.createInsecure();
    } else if (opts.caCertFile) {
      creds = grpc.credentials.createSsl(fs.readFileSync(opts.caCertFile));
    } else {
      creds = grpc.credentials.createSsl();
    }

    this.grpcClient = new ServiceCtor(endpoint, creds) as unknown as VaultGrpcClient;
    this.secret = opts.secret;
  }

  private meta(): grpc.Metadata {
    const m = new grpc.Metadata();
    if (this.secret) m.add('x-vault-secret', this.secret);
    return m;
  }

  private call<T>(method: keyof VaultGrpcClient, req: unknown): Promise<T> {
    return new Promise((resolve, reject) => {
      (this.grpcClient[method] as Function).call(
        this.grpcClient,
        req,
        this.meta(),
        (err: grpc.ServiceError | null, resp: T) => {
          if (err) reject(err);
          else resolve(resp);
        },
      );
    });
  }

  /**
   * Creates a threshold (MPC + TSS) wallet via distributed key generation.
   *
   * Every wallet is threshold-custodied; there is no custody model to select.
   * The returned address is produced by DKG and is unrelated to any address the
   * wallet id may have had under the removed single-key custody model.
   *
   * With `nodeKeys` configured this THROWS unless enough distinct signer nodes
   * proved they hold a share. Verification is not advisory: a caller that
   * configured node keys asked for a wallet it can prove is threshold-backed, so
   * an unprovable one is an error. Returning it with a flag to check would be a
   * flag that gets ignored, and the funds go to the address either way.
   */
  async create(markup: string, walletId: string): Promise<WalletCreateResult> {
    const resp = await this.call<any>('Create', { markup, walletId });
    const attestations: Attestation[] = (resp.attestations ?? []).map((a: any) => ({
      partyId: Number(a.partyId),
      signature: new Uint8Array(a.signature ?? []),
    }));
    const out: WalletCreateResult = {
      walletId: resp.walletId,
      ecdsaPubKey: resp.ecdsaPubkey,
      attestations,
      groupPubkey: new Uint8Array(resp.groupPubkey ?? []),
      threshold: Number(resp.threshold ?? 0),
      allIds: (resp.allIds ?? []).map(Number),
      attested: false,
    };
    if (!this.nodeKeys) return out;

    try {
      verifyAttestations(
        {
          walletId: out.walletId,
          address: out.ecdsaPubKey,
          groupPubkey: out.groupPubkey,
          threshold: out.threshold,
          allIds: out.allIds,
        },
        attestations,
        this.nodeKeys,
        // The client's own configured threshold wins over the one in the
        // response, which a compromised server would otherwise get to choose.
        this.attestationThreshold,
      );
    } catch (err) {
      throw new Error(
        `refusing wallet ${out.walletId}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    out.attested = true;
    return out;
  }

  async getWallet(walletId: string): Promise<Wallet> {
    const resp = await this.call<any>('GetWallet', { walletId });
    return {
      walletId: resp.walletId,
      markup: resp.markup,
      address: resp.address,
      groupPubkey: new Uint8Array(resp.groupPubkey ?? []),
      threshold: Number(resp.threshold ?? 0),
      allIds: (resp.allIds ?? []).map(Number),
    };
  }

  async signByAddress(args: SignArgs): Promise<Uint8Array> {
    const resp = await this.call<any>('SignByAddress', {
      address: args.address,
      requestId: args.requestId,
      network: args.network,
      chainId: bigIntToBytes(args.chainId),
      transaction: Buffer.from(args.transaction),
    });
    return new Uint8Array(resp.signedTransaction);
  }

  async signByWallet(args: SignByWalletArgs): Promise<Uint8Array> {
    const resp = await this.call<any>('SignByWallet', {
      walletId: args.walletId,
      requestId: args.requestId,
      network: args.network,
      chainId: bigIntToBytes(args.chainId),
      transaction: Buffer.from(args.transaction),
    });
    return new Uint8Array(resp.signedTransaction);
  }

  /**
   * Signs `keccak(0x19 || 0x01 || domainSeparator || typedDataHash)` and returns
   * the split signature.
   *
   * This describes nothing about what is being signed: at this layer a limit
   * order and a value-transfer action are both just keccak outputs. A vault
   * credential in enforce mode refuses a request it cannot check, so prefer
   * {@link typedDataWithAction} when the Hyperliquid payload is available.
   */
  async typedData(args: TypedDataArgs): Promise<RSVResult> {
    return this.sendTypedData(args, undefined);
  }

  /**
   * `typedData` plus a description of the Hyperliquid L1 action being signed, so
   * the vault can authorize the action rather than only sign its hash.
   *
   * See {@link HyperliquidAction}: the msgpack must be the SDK's own bytes,
   * because the vault checks that they derive the hashes in this same request.
   */
  async typedDataWithAction(args: TypedDataWithActionArgs): Promise<RSVResult> {
    return this.sendTypedData(args, actionToWire(args.action));
  }

  private async sendTypedData(
    args: TypedDataArgs,
    action: Record<string, unknown> | undefined,
  ): Promise<RSVResult> {
    const resp = await this.call<any>('TypedData', {
      requestId: args.requestId,
      network: args.network,
      chainId: bigIntToBytes(args.chainId),
      address: addressToBytes(args.address),
      domainSeparator: Buffer.from(args.domainSeparator),
      typedDataHash: Buffer.from(args.typedDataHash),
      action,
    });
    return {
      r: bytesToBigInt(resp.r),
      s: bytesToBigInt(resp.s),
      v: resp.v,
    };
  }

  close(): void {
    this.grpcClient.close();
  }
}
