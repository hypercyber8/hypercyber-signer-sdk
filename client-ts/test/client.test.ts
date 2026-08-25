/**
 * create() against a stub vault, to pin the behaviour that actually protects
 * funds: with node keys configured, a wallet whose attestations do not check out
 * never reaches the caller.
 *
 * The response bodies are the Go-generated fixtures, so this is also the end to
 * end check that the fields survive the proto round-trip with the names and
 * shapes verification expects — a wrong field name here would zero the group key
 * or drop the attestations, and every wallet would be refused for a reason that
 * has nothing to do with the signers.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { after, before, describe, it } from 'node:test';

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';

import { VaultClient } from '../src/client';

const fixtures = JSON.parse(readFileSync(path.join(__dirname, 'fixtures.json'), 'utf8'));
const protoPath = path.join(__dirname, '..', 'proto', 'vault.proto');

const bytes = (hex: string) => Buffer.from(hex, 'hex');
const nodeKeys = fixtures.nodes.map((n: any) => ({ partyId: n.partyId, pubKey: n.pubKey }));

function createResponse(attestations: { partyId: number; signature: string }[]) {
  return {
    walletId: fixtures.statement.walletId,
    ecdsaPubkey: fixtures.statement.address,
    attestations: attestations.map((a) => ({ partyId: a.partyId, signature: bytes(a.signature) })),
    groupPubkey: bytes(fixtures.statement.groupPubkey),
    threshold: fixtures.statement.threshold,
    allIds: fixtures.statement.allIds,
  };
}

/** A vault that returns whatever the current test tells it to. */
class StubVault {
  private server = new grpc.Server();
  response: unknown = createResponse(fixtures.genuine);
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
      Create: (_call: unknown, cb: (e: null, r: unknown) => void) => cb(null, this.response),
    });
    this.port = await new Promise<number>((resolve, reject) => {
      this.server.bindAsync(
        '127.0.0.1:0',
        grpc.ServerCredentials.createInsecure(),
        (err, port) => (err ? reject(err) : resolve(port)),
      );
    });
  }

  stop(): void {
    this.server.forceShutdown();
  }
}

describe('create()', () => {
  const vault = new StubVault();
  before(async () => {
    await vault.start();
  });
  after(() => {
    vault.stop();
  });

  const connect = (opts: Record<string, unknown> = {}) =>
    new VaultClient(`127.0.0.1:${vault.port}`, { insecure: true, protoPath, ...opts });

  it('surfaces the attestations, group key, threshold and party ids', async () => {
    vault.response = createResponse(fixtures.genuine);
    const c = connect();
    try {
      const res = await c.create('default', 'ignored');
      assert.equal(res.attestations.length, fixtures.genuine.length);
      assert.equal(
        Buffer.from(res.groupPubkey).toString('hex'),
        fixtures.statement.groupPubkey,
      );
      assert.equal(res.threshold, fixtures.statement.threshold);
      assert.deepEqual(res.allIds, fixtures.statement.allIds);
      // Nothing was configured to check them against, so the caller is still
      // taking the frontend's word and must be told so.
      assert.equal(res.attested, false);
    } finally {
      c.close();
    }
  });

  it('reports attested when the configured nodes really signed', async () => {
    vault.response = createResponse(fixtures.genuine);
    const c = connect({ nodeKeys, attestationThreshold: 2 });
    try {
      const res = await c.create('default', 'ignored');
      assert.equal(res.attested, true);
    } finally {
      c.close();
    }
  });

  // The whole point: an unverifiable wallet is an error, not a flag. A flag gets
  // ignored and the funds go to the address anyway.
  it('throws rather than returning a wallet whose attestations were forged', async () => {
    vault.response = createResponse(fixtures.forged);
    const c = connect({ nodeKeys });
    try {
      await assert.rejects(c.create('default', 'ignored'), /refusing wallet/);
    } finally {
      c.close();
    }
  });

  it('throws when a single node attests under several party ids', async () => {
    vault.response = createResponse(fixtures.replayed);
    const c = connect({ nodeKeys });
    try {
      await assert.rejects(c.create('default', 'ignored'), /refusing wallet/);
    } finally {
      c.close();
    }
  });

  // A server that dropped the attestations entirely — or a single-host one
  // answering a client that expects a distributed deployment — must not pass.
  it('throws when the response carries no attestations at all', async () => {
    vault.response = createResponse([]);
    const c = connect({ nodeKeys });
    try {
      await assert.rejects(c.create('default', 'ignored'), /refusing wallet/);
    } finally {
      c.close();
    }
  });

  it('will not accept a server-chosen threshold below its own', async () => {
    // The server claims 2-of-3 and supplies two genuine signatures; the caller
    // requires three. Letting the response decide how many are enough would let
    // a compromised one decide "one".
    vault.response = createResponse(fixtures.genuine);
    const c = connect({ nodeKeys, attestationThreshold: 3 });
    try {
      await assert.rejects(c.create('default', 'ignored'), /below its threshold of 3/);
    } finally {
      c.close();
    }
  });
});

describe('client construction', () => {
  it('refuses an empty nodeKeys array instead of silently disabling verification', () => {
    assert.throws(
      () => new VaultClient('127.0.0.1:1', { insecure: true, protoPath, nodeKeys: [] }),
      /would disable the attestation verification/,
    );
  });

  it('refuses one public key configured under two party ids', () => {
    assert.throws(
      () =>
        new VaultClient('127.0.0.1:1', {
          insecure: true,
          protoPath,
          nodeKeys: [nodeKeys[0], { partyId: 9, pubKey: nodeKeys[0].pubKey }],
        }),
      /same public key/,
    );
  });
});
