export {
  VaultClient,
  type ClientOptions,
  type WalletCreateResult,
  type RSVResult,
  type SignArgs,
  type SignByWalletArgs,
  type TypedDataArgs,
  type TypedDataWithActionArgs,
  type TypedDataWithMessageArgs,
  type HyperliquidAction,
  type TypedDataMessage,
  type SetCodeArgs,
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
