/**
 * What the client puts on the wire when it DESCRIBES a payload.
 *
 * The vault does not accept a domain separator from a description — it rebuilds
 * one from the name, version, chainId and verifyingContract it receives, and
 * refuses the request unless the rebuilt value is the separator being signed.
 * So the encoding of those four parts is the whole contract, and getting it
 * wrong fails in the least useful way available: the request is refused with a
 * message that names no field, or — for a credential not yet in enforce mode —
 * the vault logs a description it cannot read and SIGNS ANYWAY, leaving the
 * mistake to surface the day enforcement is turned on.
 *
 * These tests pin the encoding against a value neither this client nor the vault
 * produced: USDC's own DOMAIN_SEPARATOR() on Arbitrum Sepolia, the domain a real
 * 1 USDC EIP-3009 transfer has already been signed and mined under.
 *
 * They go through a real grpc server, so the proto field names and the
 * bytes/string choices are exercised rather than asserted about.
 */
import { strict as assert } from 'node:assert';
import * as path from 'node:path';
import { after, before, describe, it } from 'node:test';

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { keccak_256 } from '@noble/hashes/sha3';

import { VaultClient } from '../src/client';

const protoPath = path.join(__dirname, '..', 'proto', 'vault.proto');

/** USDC on Arbitrum Sepolia, and the domain separator the contract itself reports. */
const USDC = '0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d';
const DOMAIN_NAME = 'USD Coin';
const DOMAIN_VERSION = '2';
const CHAIN_ID = 421614n;
const DOMAIN_SEPARATOR = '0x85944e1292d007732838d6eadfa67589b78ffcededbd4df60488d0af251308bb';

const HOLDER = '0x8f426e67858a9febf31bb76e155d1949d6cfd23f';
const DEST = '0x4d5fd9c32f92e1b0ba381b3d9ac5514c64e4080c';

function wireHex(v: Uint8Array): string { return '0x' + Buffer.from(v).toString('hex'); }
function wireBigInt(v: Uint8Array): bigint {
  const h = Buffer.from(v).toString('hex');
  return h ? BigInt('0x' + h) : 0n;
}
const AUTH_NONCE = '0x' + 'ab'.repeat(32);

const utf8 = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array | Buffer) => '0x' + Buffer.from(b).toString('hex');

function word(b: Buffer): Buffer {
  const out = Buffer.alloc(32);
  b.copy(out, 32 - b.length);
  return out;
}

function uint256Word(n: bigint): Buffer {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  return word(Buffer.from(h, 'hex'));
}

/**
 * keccak(abi.encode(EIP712DOMAIN_TYPEHASH, keccak(name), keccak(version),
 * chainId, verifyingContract)) — the rebuild the vault performs on the parts it
 * receives, written out independently here so this checks the WIRE and not the
 * client's own idea of what it sent.
 *
 * chainId goes through BigInt(), so a wire value that is not a decimal string —
 * bytes, hex, a JS number that lost precision — fails here rather than being
 * quietly reinterpreted.
 */
function separatorFromParts(d: { name: string; version: string; chainId: string; verifyingContract: string }): string {
  const typeHash = keccak_256(
    utf8('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
  );
  assert.match(d.chainId, /^[0-9]+$/, `domain chainId must reach the vault as a decimal string, got ${d.chainId}`);
  return hex(
    keccak_256(
      Buffer.concat([
        Buffer.from(typeHash),
        Buffer.from(keccak_256(utf8(d.name))),
        Buffer.from(keccak_256(utf8(d.version))),
        uint256Word(BigInt(d.chainId)),
        word(Buffer.from(d.verifyingContract.replace(/^0x/i, ''), 'hex')),
      ]),
    ),
  );
}

/** The EIP-3009 struct hash, so the request carries hashes that belong together. */
function transferWithAuthorizationHash(f: Record<string, string>): Buffer {
  const typeHash = keccak_256(
    utf8(
      'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)',
    ),
  );
  return Buffer.from(
    keccak_256(
      Buffer.concat([
        Buffer.from(typeHash),
        word(Buffer.from(f.from.slice(2), 'hex')),
        word(Buffer.from(f.to.slice(2), 'hex')),
        uint256Word(BigInt(f.value)),
        uint256Word(BigInt(f.validAfter)),
        uint256Word(BigInt(f.validBefore)),
        Buffer.from(f.nonce.slice(2), 'hex'),
      ]),
    ),
  );
}

const FIELDS = {
  from: HOLDER,
  to: DEST,
  value: '1000000',
  validAfter: '0',
  validBefore: '1785200000',
  nonce: AUTH_NONCE,
};

/** A vault that answers every TypedData call and keeps the request it was given. */
class CapturingVault {
  private server = new grpc.Server();
  request: any = null;
  port = 0;

  async start(): Promise<void> {
    const def = protoLoader.loadSync(protoPath, {
      keepCase: false,
      longs: String,
      enums: Number,
      defaults: true,
      oneofs: true,
      bytes: Buffer,
    });
    const pkg = grpc.loadPackageDefinition(def) as any;
    this.server.addService(pkg.vault.v1.VaultService.service, {
      TypedData: (call: any, cb: (e: null, r: unknown) => void) => {
        this.request = call.request;
        cb(null, { r: Buffer.alloc(32, 1), s: Buffer.alloc(32, 2), v: 27 });
      },
    });
    this.port = await new Promise<number>((resolve, reject) => {
      this.server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, port) =>
        err ? reject(err) : resolve(port),
      );
    });
  }

  stop(): void {
    this.server.forceShutdown();
  }
}

describe('typedDataWithMessage()', () => {
  const vault = new CapturingVault();
  before(async () => {
    await vault.start();
  });
  after(() => {
    vault.stop();
  });

  const connect = () => new VaultClient(`127.0.0.1:${vault.port}`, { insecure: true, protoPath });

  const message = {
    primaryType: 'TransferWithAuthorization',
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId: CHAIN_ID,
    verifyingContract: USDC,
    fields: FIELDS,
  };

  const send = async () => {
    const c = connect();
    try {
      await c.typedDataWithMessage({
        requestId: 'req-1',
        address: HOLDER,
        network: 'ethereum',
        chainId: CHAIN_ID,
        domainSeparator: Buffer.from(DOMAIN_SEPARATOR.slice(2), 'hex'),
        typedDataHash: transferWithAuthorizationHash(FIELDS),
        message,
      });
    } finally {
      c.close();
    }
    return vault.request;
  };

  // The one that matters. If the parts arrive in a shape the vault rebuilds
  // differently, every honest request is refused and nothing says which field
  // was wrong.
  it('sends a domain that rebuilds to the separator the token really uses', async () => {
    const req = await send();
    assert.equal(separatorFromParts(req.message.domain), DOMAIN_SEPARATOR);
    // And that rebuilt value is the separator the request asks to sign under —
    // which is the exact comparison the vault makes before it will vouch for
    // the description.
    assert.equal(separatorFromParts(req.message.domain), hex(req.domainSeparator));
  });

  it('sends the four domain parts, chainId decimal and the contract as hex', async () => {
    const req = await send();
    assert.equal(req.message.domain.name, DOMAIN_NAME);
    assert.equal(req.message.domain.version, DOMAIN_VERSION);
    assert.equal(req.message.domain.chainId, '421614');
    assert.equal(req.message.domain.verifyingContract.toLowerCase(), USDC.toLowerCase());
  });

  it('names the primary type and sends every signed field as a string', async () => {
    const req = await send();
    assert.equal(req.message.primaryType, 'TransferWithAuthorization');
    assert.deepEqual(req.message.fields, FIELDS);
    for (const [name, value] of Object.entries(req.message.fields)) {
      assert.equal(typeof value, 'string', `field ${name} must reach the vault as a string`);
    }
  });

  // Two descriptions of one digest cannot both be checked, so the vault refuses
  // a request carrying both. This client must never produce one.
  it('never sends an action beside a message', async () => {
    const req = await send();
    assert.ok(!req.action?.actionMsgpack?.length, 'a described message must not travel with an action');
  });

  it('refuses a verifyingContract that is not an address, rather than letting the vault refuse it', async () => {
    const c = connect();
    try {
      await assert.rejects(
        c.typedDataWithMessage({
          requestId: 'req-2',
          address: HOLDER,
          network: 'ethereum',
          chainId: CHAIN_ID,
          domainSeparator: Buffer.alloc(32),
          typedDataHash: Buffer.alloc(32),
          message: { ...message, verifyingContract: '0xdeadbeef' },
        }),
        /verifyingContract must be a 20-byte hex address/,
      );
    } finally {
      c.close();
    }
  });

  // A number here would be a rounded uint256, and a rounded amount authorizes a
  // transfer nobody asked for.
  it('refuses a field that is not a string', async () => {
    const c = connect();
    try {
      await assert.rejects(
        c.typedDataWithMessage({
          requestId: 'req-3',
          address: HOLDER,
          network: 'ethereum',
          chainId: CHAIN_ID,
          domainSeparator: Buffer.alloc(32),
          typedDataHash: Buffer.alloc(32),
          message: { ...message, fields: { ...FIELDS, value: 1000000 as unknown as string } },
        }),
        /field "value" is a number/,
      );
    } finally {
      c.close();
    }
  });
});

describe('typedDataWithCalibur()', () => {
  const vault = new CapturingVault();
  before(async () => { await vault.start(); });
  after(() => { vault.stop(); });

  it('sends every nested call and salted-domain input as typed protobuf fields', async () => {
    const c = new VaultClient(`127.0.0.1:${vault.port}`, { insecure: true, protoPath });
    try {
      await c.typedDataWithCalibur({
        requestId: 'calibur-1', address: HOLDER, network: 'ethereum', chainId: CHAIN_ID,
        domainSeparator: Buffer.alloc(32, 1), typedDataHash: Buffer.alloc(32, 2),
        calibur: {
          chainId: CHAIN_ID, wallet: HOLDER,
          implementation: '0x000000009B1D0aF20D8C6d0A44e162d11F9b8f00',
          calls: [{ to: USDC, value: 123n, data: Buffer.from('095ea7b3', 'hex') }],
          revertOnFailure: true, nonce: (1n << 200n) + 7n,
          keyHash: '0x' + '00'.repeat(32), executor: '0x' + '00'.repeat(20), deadline: 1_800_000_000n,
        },
      });
    } finally { c.close(); }
    const req = vault.request;
    assert.equal(wireBigInt(req.calibur.chainId), CHAIN_ID);
    assert.equal(wireHex(req.calibur.wallet).toLowerCase(), HOLDER.toLowerCase());
    assert.equal(req.calibur.calls.length, 1);
    assert.equal(wireBigInt(req.calibur.calls[0].value), 123n);
    assert.equal(wireHex(req.calibur.calls[0].data), '0x095ea7b3');
    assert.ok(!req.action?.actionMsgpack?.length && !req.message?.primaryType);
  });

  it('rejects malformed fixed-width values before they reach gRPC', async () => {
    const c = new VaultClient(`127.0.0.1:${vault.port}`, { insecure: true, protoPath });
    try {
      await assert.rejects(c.typedDataWithCalibur({
        requestId: 'calibur-bad-key', address: HOLDER, network: 'ethereum', chainId: CHAIN_ID,
        domainSeparator: Buffer.alloc(32, 1), typedDataHash: Buffer.alloc(32, 2),
        calibur: {
          chainId: CHAIN_ID, wallet: HOLDER,
          implementation: '0x000000009B1D0aF20D8C6d0A44e162d11F9b8f00',
          calls: [{ to: USDC, value: 1n, data: Buffer.alloc(0) }],
          revertOnFailure: true, nonce: 1n, keyHash: '0x1234',
          executor: '0x' + '00'.repeat(20), deadline: 1_800_000_000n,
        },
      }), /calibur\.keyHash must be 32 bytes/);
    } finally { c.close(); }
  });
});

describe('typedData() and typedDataWithAction()', () => {
  const vault = new CapturingVault();
  before(async () => {
    await vault.start();
  });
  after(() => {
    vault.stop();
  });

  const connect = () => new VaultClient(`127.0.0.1:${vault.port}`, { insecure: true, protoPath });

  const base = {
    requestId: 'req-1',
    address: HOLDER,
    network: 'ethereum',
    chainId: CHAIN_ID,
    domainSeparator: Buffer.alloc(32, 3),
    typedDataHash: Buffer.alloc(32, 4),
  };

  // A bare typedData describes nothing, and must not look as though it did.
  it('sends neither an action nor a message', async () => {
    const c = connect();
    try {
      await c.typedData(base);
    } finally {
      c.close();
    }
    assert.ok(!vault.request.message?.primaryType, 'bare typedData must not carry a message');
    assert.ok(!vault.request.action?.actionMsgpack?.length, 'bare typedData must not carry an action');
  });

  it('sends the action msgpack unchanged, with a uint64 nonce that survives above 2^53', async () => {
    const c = connect();
    const msgpack = Buffer.from('82a474797065a56f72646572', 'hex');
    try {
      await c.typedDataWithAction({
        ...base,
        // Above 2^53, so a nonce that went through a JS number would come back
        // as ...984 and derive a different action hash.
        action: { actionMsgpack: msgpack, nonce: 18014398509481985n, vaultAddress: '', isMainnet: false },
      });
    } finally {
      c.close();
    }
    assert.equal(hex(vault.request.action.actionMsgpack), hex(msgpack));
    assert.equal(vault.request.action.nonce, '18014398509481985');
    assert.equal(vault.request.action.isMainnet, false);
    // Omitting the expiry and passing 0 derive different action hashes, so the
    // flag must stay false rather than describing an expiry of zero.
    assert.equal(vault.request.action.hasExpiresAfter, false);
  });

  it('flags an expiry that was given, so zero is not mistaken for absent', async () => {
    const c = connect();
    try {
      await c.typedDataWithAction({
        ...base,
        action: { actionMsgpack: Buffer.from([0x80]), nonce: 1, expiresAfter: 0n, isMainnet: true },
      });
    } finally {
      c.close();
    }
    assert.equal(vault.request.action.hasExpiresAfter, true);
    assert.equal(vault.request.action.expiresAfter, '0');
  });
});
