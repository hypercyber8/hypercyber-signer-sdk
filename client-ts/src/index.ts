export {
  VaultClient,
  type ClientOptions,
  type WalletCreateResult,
  type Wallet,
  type RSVResult,
  type SignArgs,
  type SignByWalletArgs,
  type TypedDataArgs,
  type TypedDataWithActionArgs,
  type HyperliquidAction,
} from './client';

export {
  statementDigest,
  validateNodeKeys,
  verifyAttestations,
  parseNodeKeys,
  type Statement,
  type Attestation,
  type NodeKey,
  type ByteInput,
} from './attest';
