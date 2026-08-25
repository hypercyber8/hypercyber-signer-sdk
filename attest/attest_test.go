package attest

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func newNode(t *testing.T, partyID int) (string, NodeKey) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(crypto.FromECDSA(key)), NodeKey{
		PartyID: partyID,
		PubKey:  crypto.CompressPubkey(&key.PublicKey),
	}
}

func testStatement() Statement {
	return Statement{
		WalletID:  "wallet-1",
		Address:   "0x1111111111111111111111111111111111111111",
		GroupPub:  make([]byte, 33),
		Threshold: 2,
		AllIDs:    []int{1, 2, 3},
	}
}

// The honest path: t of the configured nodes attest, and the client accepts.
func TestThresholdOfConfiguredNodesVerifies(t *testing.T) {
	k1, n1 := newNode(t, 1)
	k2, n2 := newNode(t, 2)
	_, n3 := newNode(t, 3)
	s := testStatement()

	a1, err := Sign(k1, 1, s)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := Sign(k2, 2, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(s, []*Attestation{a1, a2}, []NodeKey{n1, n2, n3}, 2); err != nil {
		t.Fatalf("two genuine attestations were rejected: %v", err)
	}
}

// The attack this closes: a frontend that skipped the ceremony and generated a
// key it knows can sign for the address, but it cannot produce attestations from
// the nodes' identity keys.
func TestFrontendCannotForgeAttestations(t *testing.T) {
	_, n1 := newNode(t, 1)
	_, n2 := newNode(t, 2)
	_, n3 := newNode(t, 3)
	s := testStatement()

	// The frontend holds some key of its own and signs with it, claiming to be
	// each party in turn.
	rogueHex, _ := newNode(t, 0)
	var forged []*Attestation
	for _, id := range []int{1, 2, 3} {
		a, err := Sign(rogueHex, id, s)
		if err != nil {
			t.Fatal(err)
		}
		forged = append(forged, a)
	}
	if err := Verify(s, forged, []NodeKey{n1, n2, n3}, 2); err == nil {
		t.Fatal("attestations signed by an unconfigured key were accepted")
	}
}

// One node's attestation replayed under several party ids must count once. Any
// other behaviour would let a single compromised node satisfy the threshold.
func TestReplayedAttestationCountsOnce(t *testing.T) {
	k1, n1 := newNode(t, 1)
	_, n2 := newNode(t, 2)
	_, n3 := newNode(t, 3)
	s := testStatement()

	a1, err := Sign(k1, 1, s)
	if err != nil {
		t.Fatal(err)
	}
	// Same signature, presented three times, twice under other parties' ids.
	dup := []*Attestation{
		a1,
		{PartyID: 2, Signature: a1.Signature},
		{PartyID: 3, Signature: a1.Signature},
	}
	if err := Verify(s, dup, []NodeKey{n1, n2, n3}, 2); err == nil {
		t.Fatal("one node's attestation replayed under other ids satisfied the threshold")
	}
}

// An attestation is bound to its exact statement. Changing any field must
// invalidate it, or a frontend could attest to one wallet and hand over another.
func TestAttestationIsBoundToEveryField(t *testing.T) {
	k1, n1 := newNode(t, 1)
	k2, n2 := newNode(t, 2)
	s := testStatement()
	a1, _ := Sign(k1, 1, s)
	a2, _ := Sign(k2, 2, s)
	nodes := []NodeKey{n1, n2}

	mutations := map[string]func(Statement) Statement{
		"wallet id": func(x Statement) Statement { x.WalletID = "other"; return x },
		"address": func(x Statement) Statement {
			x.Address = "0x2222222222222222222222222222222222222222"
			return x
		},
		"group key": func(x Statement) Statement {
			pub := make([]byte, 33)
			pub[0] = 0x02
			x.GroupPub = pub
			return x
		},
		"threshold":   func(x Statement) Statement { x.Threshold = 3; return x },
		"party set":   func(x Statement) Statement { x.AllIDs = []int{1, 2, 4}; return x },
		"party count": func(x Statement) Statement { x.AllIDs = []int{1, 2}; return x },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := Verify(mutate(s), []*Attestation{a1, a2}, nodes, 2); err == nil {
				t.Fatal("attestations verified against a different statement")
			}
		})
	}
}

// Party-id order must not change the digest: the same group described in a
// different order is the same group.
func TestPartyOrderDoesNotChangeTheDigest(t *testing.T) {
	a := testStatement()
	b := testStatement()
	b.AllIDs = []int{3, 1, 2}
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatal("reordering party ids changed the attestation digest")
	}
}

// Fields are length-prefixed so a boundary between two of them cannot be moved.
func TestFieldBoundariesCannotBeShifted(t *testing.T) {
	a := testStatement()
	a.WalletID = "ab"
	a.Address = "0xc111111111111111111111111111111111111111"
	b := testStatement()
	b.WalletID = "a"
	b.Address = "0xbc11111111111111111111111111111111111111"
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da == db {
		t.Fatal("moving the boundary between two fields produced the same digest")
	}
}

// A client with no configured node keys must fail closed. Accepting attestations
// it cannot check would mean trusting the frontend's word — the exact thing this
// package exists to stop.
func TestNoConfiguredNodesFailsClosed(t *testing.T) {
	k1, _ := newNode(t, 1)
	s := testStatement()
	a1, _ := Sign(k1, 1, s)
	if err := Verify(s, []*Attestation{a1}, nil, 2); err == nil {
		t.Fatal("verification passed with no configured node keys")
	}
	if err := Verify(s, []*Attestation{a1}, nil, 2); !strings.Contains(err.Error(), "out of band") &&
		!strings.Contains(err.Error(), "no node identity keys") {
		t.Fatalf("error does not explain the missing configuration: %v", err)
	}
}

// Malformed statements must not produce a digest at all — signing over a
// half-specified assertion would attest to something nobody can check.
func TestMalformedStatementsAreRefused(t *testing.T) {
	cases := map[string]Statement{
		"no wallet id":                 {Address: "0x1", GroupPub: make([]byte, 33), Threshold: 2, AllIDs: []int{1, 2}},
		"no address":                   {WalletID: "w", GroupPub: make([]byte, 33), Threshold: 2, AllIDs: []int{1, 2}},
		"short group key":              {WalletID: "w", Address: "0x1", GroupPub: make([]byte, 32), Threshold: 2, AllIDs: []int{1, 2}},
		"threshold below 2":            {WalletID: "w", Address: "0x1", GroupPub: make([]byte, 33), Threshold: 1, AllIDs: []int{1, 2}},
		"fewer parties than threshold": {WalletID: "w", Address: "0x1", GroupPub: make([]byte, 33), Threshold: 3, AllIDs: []int{1, 2}},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Digest(); err == nil {
				t.Fatal("a malformed statement produced a digest")
			}
		})
	}
}

// The address comparison is case-insensitive, so a checksummed address and its
// lowercase form attest to the same wallet rather than silently to two.
func TestAddressCaseDoesNotMatter(t *testing.T) {
	a := testStatement()
	a.Address = "0xAbCdEf1111111111111111111111111111111111"
	b := testStatement()
	b.Address = strings.ToLower(a.Address)
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db {
		t.Fatal("address casing changed the attestation digest")
	}
}

// A single node configured under two party ids must not satisfy a 2-of-n
// threshold by itself. Verify counts distinct party ids, so if a config file
// repeats one public key under two entries — a copy-paste, which nothing else
// would flag — that one node signs twice, is counted twice, and the threshold
// that was supposed to require two independent hosts requires one.
func TestDuplicatePublicKeyUnderTwoPartyIDsIsRejected(t *testing.T) {
	k1, n1 := newNode(t, 1)
	_, n3 := newNode(t, 3)
	// Party 2 is misconfigured with party 1's public key.
	n2 := NodeKey{PartyID: 2, PubKey: n1.PubKey}
	s := testStatement()

	// The single node holding that key attests under both ids.
	a1, err := Sign(k1, 1, s)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := Sign(k1, 2, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(s, []*Attestation{a1, a2}, []NodeKey{n1, n2, n3}, 2); err == nil {
		t.Fatal("one node satisfied a 2-of-3 threshold because its key was configured under two party ids")
	}

	// And the same set must be rejected at configuration time, before any
	// attestation is presented against it.
	if err := ValidateNodeKeys([]NodeKey{n1, n2, n3}); err == nil {
		t.Fatal("ValidateNodeKeys accepted one public key configured under two party ids")
	}
}

// The rest of the configuration contract: a party id may name exactly one node,
// keys must be well formed, and an empty set is not a valid configuration.
func TestValidateNodeKeys(t *testing.T) {
	_, n1 := newNode(t, 1)
	_, n2 := newNode(t, 2)

	if err := ValidateNodeKeys([]NodeKey{n1, n2}); err != nil {
		t.Fatalf("a well-formed node set was rejected: %v", err)
	}
	if err := ValidateNodeKeys(nil); err == nil {
		t.Fatal("an empty node set was accepted")
	}
	if err := ValidateNodeKeys([]NodeKey{n1, {PartyID: 1, PubKey: n2.PubKey}}); err == nil {
		t.Fatal("party id 1 was accepted twice")
	}
	if err := ValidateNodeKeys([]NodeKey{n1, {PartyID: 2, PubKey: n2.PubKey[:32]}}); err == nil {
		t.Fatal("a truncated public key was accepted")
	}
}
