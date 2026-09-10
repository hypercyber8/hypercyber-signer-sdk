import { strict as assert } from 'node:assert';
import * as path from 'node:path';
import { after, before, describe, it } from 'node:test';

import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';

import { VaultClient } from '../src/client';

const protoPath = path.join(__dirname, '..', 'proto', 'vault.proto');

const HOLDER = '0x8f426e67858a9febf31bb76e155d1949d6cfd23f';
const CHAIN_ID = 421614n;

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

describe('typedData() and typedDataWithAction()', () => {
  const vault = new CapturingVault();
  before(async () => vault.start());
  after(() => vault.stop());

  const connect = () => new VaultClient(`127.0.0.1:${vault.port}`, { insecure: true, protoPath });
  const base = {
    requestId: 'req-1',
    address: HOLDER,
    network: 'hyperliquid',
    chainId: CHAIN_ID,
    domainSeparator: Buffer.alloc(32, 3),
    typedDataHash: Buffer.alloc(32, 4),
  };

  it('sends no action for a bare typed-data request', async () => {
    const client = connect();
    try {
      await client.typedData(base);
    } finally {
      client.close();
    }
    assert.ok(!vault.request.action?.actionMsgpack?.length);
  });

  it('preserves the action bytes and a nonce above JavaScript safe integer range', async () => {
    const client = connect();
    const msgpack = Buffer.from('82a474797065a56f72646572', 'hex');
    try {
      await client.typedDataWithAction({
        ...base,
        action: { actionMsgpack: msgpack, nonce: 18014398509481985n, vaultAddress: '', isMainnet: false },
      });
    } finally {
      client.close();
    }

    assert.deepEqual(vault.request.action.actionMsgpack, msgpack);
    assert.equal(vault.request.action.nonce, '18014398509481985');
    assert.equal(vault.request.action.hasExpiresAfter, false);
  });

  it('distinguishes an expiry of zero from an omitted expiry', async () => {
    const client = connect();
    try {
      await client.typedDataWithAction({
        ...base,
        action: { actionMsgpack: Buffer.from([0x80]), nonce: 1, expiresAfter: 0n, isMainnet: true },
      });
    } finally {
      client.close();
    }

    assert.equal(vault.request.action.hasExpiresAfter, true);
    assert.equal(vault.request.action.expiresAfter, '0');
  });
});
