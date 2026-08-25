import { VaultClient } from '../src';

async function main() {
  const client = new VaultClient('localhost:50051', {
    secret: process.env.VAULT_SECRET ?? 'dev-secret',
    insecure: true,
  });

  try {
    // Every wallet uses threshold ECDSA. There is no custody
    // model to select — the address comes out of a distributed key generation
    // ceremony and no single node ever holds the key.
    const wallet = await client.create('demo', 'wallet-001');
    console.log('created:', wallet);

    const sig = await client.typedData({
      requestId: 'req-1',
      address: wallet.ecdsaPubKey,
      network: 'ethereum',
      chainId: 1n,
      domainSeparator: Buffer.alloc(32, 0xaa),
      typedDataHash: Buffer.alloc(32, 0xbb),
    });
    console.log('typedData rsv:', sig);
  } finally {
    client.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
