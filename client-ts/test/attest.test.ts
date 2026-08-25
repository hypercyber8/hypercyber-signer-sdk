/**
 * These run against fixtures.json, which is produced by the Go `attest` package
 * (`go run ./client-ts/test/gen-fixtures`).
 *
 * That is the point of the file. Two implementations of a digest, each written
 * from the same description, agree with the description and not necessarily with
 * each other — and a digest that differs by one byte does not fail loudly, it
 * makes every genuine attestation look forged, so a caller that turned
 * verification on would reject every wallet the vault ever creates. Checking
 * against the Go implementation's OUTPUT is what catches that.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { describe, it } from 'node:test';

import {
  type Attestation,
  type NodeKey,
  type Statement,
  parseNodeKeys,
  statementDigest,
  validateNodeKeys,
  verifyAttestations,
} from '../src/attest';

interface JsonStatement {
  walletId: string;
  address: string;
  groupPubkey: string;
  threshold: number;
  allIds: number[];
}

interface Fixtures {
  statement: JsonStatement;
  digest: string;
  nodes: { partyId: number; pubKey: string }[];
  threshold: number;
  genuine: { partyId: number; signature: string }[];
  forged: { partyId: number; signature: string }[];
  replayed: { partyId: number; signature: string }[];
  mutatedStatements: { name: string; statement: JsonStatement }[];
  reorderedIds: JsonStatement;
  duplicateKeyNodes: { partyId: number; pubKey: string }[];
  selfSignedUnderTwoIds: { partyId: number; signature: string }[];
}

const fixtures: Fixtures = JSON.parse(
  readFileSync(path.join(__dirname, 'fixtures.json'), 'utf8'),
);

const stmt = (s: JsonStatement): Statement => ({
  walletId: s.walletId,
  address: s.address,
  groupPubkey: s.groupPubkey,
  threshold: s.threshold,
  allIds: s.allIds,
});
const atts = (a: { partyId: number; signature: string }[]): Attestation[] => a;
const nodes = (n: { partyId: number; pubKey: string }[]): NodeKey[] => n;

const statement = stmt(fixtures.statement);
const configured = nodes(fixtures.nodes);
const threshold = fixtures.threshold;

describe('statement digest', () => {
  it('reproduces the digest the Go implementation signs', () => {
    assert.equal(Buffer.from(statementDigest(statement)).toString('hex'), fixtures.digest);
  });

  it('does not depend on party-id order: the same group in a different order is the same group', () => {
    assert.equal(
      Buffer.from(statementDigest(stmt(fixtures.reorderedIds))).toString('hex'),
      fixtures.digest,
    );
  });

  it('sorts party ids numerically, not lexicographically', () => {
    // The default JavaScript sort would put 10 before 2 and produce a digest no
    // signer ever signed — and, being a plausible-looking 32 bytes, it would
    // fail as "unattested wallet" rather than as the bug it is.
    const ascending = { ...statement, allIds: [2, 10, 3] };
    const shuffled = { ...statement, allIds: [10, 3, 2] };
    assert.equal(
      Buffer.from(statementDigest(ascending)).toString('hex'),
      Buffer.from(statementDigest(shuffled)).toString('hex'),
    );
  });

  it('ignores address casing, so a checksummed address is not a second wallet', () => {
    const lowered = { ...statement, address: statement.address.toLowerCase() };
    assert.equal(Buffer.from(statementDigest(lowered)).toString('hex'), fixtures.digest);
  });

  it('length-prefixes fields so a boundary between two of them cannot be moved', () => {
    const a = { ...statement, walletId: 'ab', address: '0xc1' };
    const b = { ...statement, walletId: 'a', address: '0xbc1' };
    assert.notEqual(
      Buffer.from(statementDigest(a)).toString('hex'),
      Buffer.from(statementDigest(b)).toString('hex'),
    );
  });

  it('refuses a half-specified statement rather than hashing it', () => {
    const cases: [string, Statement][] = [
      ['no wallet id', { ...statement, walletId: '' }],
      ['no address', { ...statement, address: '' }],
      ['short group key', { ...statement, groupPubkey: '02'.repeat(16) }],
      ['threshold below 2', { ...statement, threshold: 1 }],
      ['fewer parties than threshold', { ...statement, threshold: 3, allIds: [1, 2] }],
    ];
    for (const [name, bad] of cases) {
      assert.throws(() => statementDigest(bad), Error, `${name} produced a digest`);
    }
  });
});

describe('verification', () => {
  it('accepts a threshold of genuine attestations', () => {
    verifyAttestations(statement, atts(fixtures.genuine), configured, threshold);
  });

  // The attack this closes: a frontend that skipped the ceremony and generated a
  // key it knows can sign for the address, but it cannot produce attestations
  // from the nodes' identity keys.
  it('rejects attestations signed by an unconfigured key', () => {
    assert.throws(
      () => verifyAttestations(statement, atts(fixtures.forged), configured, threshold),
      /below its threshold/,
    );
  });

  // One node's attestation replayed under several ids must count once, or a
  // single compromised node satisfies the threshold by itself. Here each replay
  // is caught by the recovered key not matching the id it claims.
  it('counts one node replayed under three party ids once', () => {
    assert.throws(
      () => verifyAttestations(statement, atts(fixtures.replayed), configured, threshold),
      /below its threshold/,
    );
  });

  // The same replay under the id it genuinely belongs to. Nothing about this
  // signature is invalid, so only counting DISTINCT parties stops it — a tally
  // of valid signatures would reach two and let one node clear a 2-of-3.
  it('counts one party submitted twice once', () => {
    assert.throws(
      () =>
        verifyAttestations(
          statement,
          atts([fixtures.genuine[0], fixtures.genuine[0]]),
          configured,
          threshold,
        ),
      /below its threshold/,
    );
  });

  it('binds the attestation to every field of the statement', () => {
    for (const m of fixtures.mutatedStatements) {
      assert.throws(
        () => verifyAttestations(stmt(m.statement), atts(fixtures.genuine), configured, threshold),
        Error,
        `genuine attestations verified against a statement with a mutated ${m.name}`,
      );
    }
  });

  it('rejects an attestation from a party the caller does not know', () => {
    const unknown = configured.filter((n) => n.partyId !== 2);
    assert.throws(
      () => verifyAttestations(statement, atts(fixtures.genuine), unknown, threshold),
      /below its threshold/,
    );
  });

  it('fails closed with no configured node keys', () => {
    assert.throws(
      () => verifyAttestations(statement, atts(fixtures.genuine), [], threshold),
      /no node identity keys configured/,
    );
  });

  it('refuses a threshold below 2', () => {
    assert.throws(
      () => verifyAttestations(statement, atts(fixtures.genuine), configured, 1),
      /below 2/,
    );
  });

  it('refuses one node configured under two party ids, before counting with it', () => {
    const dup = nodes(fixtures.duplicateKeyNodes);
    assert.throws(
      () =>
        verifyAttestations(statement, atts(fixtures.selfSignedUnderTwoIds), dup, threshold),
      /same public key/,
    );
    assert.throws(() => validateNodeKeys(dup), /same public key/);
  });
});

describe('node key configuration', () => {
  it('accepts a well-formed set', () => {
    validateNodeKeys(configured);
  });

  it('rejects an empty set, a repeated party id, and a truncated key', () => {
    assert.throws(() => validateNodeKeys([]), /no node identity keys configured/);
    assert.throws(
      () => validateNodeKeys([configured[0], { partyId: 1, pubKey: configured[1].pubKey }]),
      /configured more than once/,
    );
    assert.throws(
      () =>
        validateNodeKeys([
          configured[0],
          { partyId: 2, pubKey: (configured[1].pubKey as string).slice(0, 20) },
        ]),
      /33 compressed bytes/,
    );
  });

  it('parses a configuration string and verifies with the result', () => {
    const spec = fixtures.nodes.map((n) => `${n.partyId}:${n.pubKey}`).join(',');
    verifyAttestations(statement, atts(fixtures.genuine), parseNodeKeys(spec), threshold);
  });

  it('refuses an empty configuration string rather than silently disabling verification', () => {
    assert.throws(() => parseNodeKeys('  '), /would disable attestation verification/);
    assert.throws(() => parseNodeKeys('1'), /partyId:publicKeyHex/);
  });
});
