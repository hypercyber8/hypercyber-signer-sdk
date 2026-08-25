// Command gen-fixtures writes the attestation fixtures the TypeScript client's
// tests run against.
//
// The fixtures are produced by the Go implementation on purpose. A TypeScript
// digest written from the same prose the Go one was written from would agree
// with the prose while disagreeing with the bytes, and verification would then
// silently never pass — an address would look unattested no matter how many
// honest nodes signed for it. Checking the two implementations against each
// other's OUTPUT is the only way that failure shows up.
//
// Everything here is deterministic — fixed private keys, RFC 6979 nonces — so
// regenerating produces the same file and a diff means a real change to the
// digest construction.
//
// Regenerate with:
//
//	go run ./client-ts/test/gen-fixtures
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/hypercyber8/hypercyber-signer-sdk/attest"
)

type jsonStatement struct {
	WalletID    string `json:"walletId"`
	Address     string `json:"address"`
	GroupPubkey string `json:"groupPubkey"`
	Threshold   int    `json:"threshold"`
	AllIDs      []int  `json:"allIds"`
}

type jsonAttestation struct {
	PartyID   int    `json:"partyId"`
	Signature string `json:"signature"`
}

type jsonNodeKey struct {
	PartyID int    `json:"partyId"`
	PubKey  string `json:"pubKey"`
}

type namedStatement struct {
	Name      string        `json:"name"`
	Statement jsonStatement `json:"statement"`
}

type fixtures struct {
	Note string `json:"note"`

	Statement jsonStatement `json:"statement"`
	// Digest is what the TypeScript implementation must reproduce byte for byte.
	// Every other case in this file is downstream of it.
	Digest    string        `json:"digest"`
	Nodes     []jsonNodeKey `json:"nodes"`
	Threshold int           `json:"threshold"`

	Genuine []jsonAttestation `json:"genuine"`
	// Forged is signed by a key no client has configured — the compromised
	// frontend that skipped the ceremony and is attesting on its own behalf.
	Forged []jsonAttestation `json:"forged"`
	// Replayed is ONE node's attestation presented under three party ids.
	Replayed []jsonAttestation `json:"replayed"`
	// MutatedStatements each differ from Statement in exactly one field, so
	// Genuine must not verify against any of them.
	MutatedStatements []namedStatement `json:"mutatedStatements"`
	// ReorderedIDs is the same group described in a different order, which must
	// hash the same.
	ReorderedIDs jsonStatement `json:"reorderedIds"`
	// DuplicateKeyNodes configures one node's public key under two party ids,
	// which must be refused before it is counted with.
	DuplicateKeyNodes []jsonNodeKey `json:"duplicateKeyNodes"`
	// SelfSignedUnderTwoIDs is that one node attesting under both of them.
	SelfSignedUnderTwoIDs []jsonAttestation `json:"selfSignedUnderTwoIds"`
}

// Fixed keys, so the file is stable across regenerations and a diff means the
// digest construction moved rather than that the generator ran again.
const (
	node1Key = "1111111111111111111111111111111111111111111111111111111111111111"
	node2Key = "2222222222222222222222222222222222222222222222222222222222222222"
	node3Key = "3333333333333333333333333333333333333333333333333333333333333333"
	rogueKey = "4444444444444444444444444444444444444444444444444444444444444444"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixtures:", err)
		os.Exit(1)
	}
}

func run() error {
	blob, err := build()
	if err != nil {
		return err
	}
	path, err := fixturesPath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o644)
}

// fixturesPath resolves the destination from this file's own location rather
// than the working directory, so the fixtures land next to the tests that read
// them no matter where `go run` was invoked from.
func fixturesPath() (string, error) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate the generator's own source path")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(self)), "fixtures.json"), nil
}

func build() ([]byte, error) {
	groupPub := make([]byte, 33)
	groupPub[0] = 0x02
	for i := 1; i < 33; i++ {
		groupPub[i] = byte(i)
	}

	stmt := attest.Statement{
		WalletID:  "bridge-9f2c1e40-0d2a-4c2b-9d1f-3a5e7c8b1234",
		Address:   "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
		GroupPub:  groupPub,
		Threshold: 2,
		AllIDs:    []int{1, 2, 3},
	}
	digest, err := stmt.Digest()
	if err != nil {
		return nil, err
	}

	nodes := []jsonNodeKey{
		{PartyID: 1, PubKey: pubOf(node1Key)},
		{PartyID: 2, PubKey: pubOf(node2Key)},
		{PartyID: 3, PubKey: pubOf(node3Key)},
	}

	genuine, err := signAll(stmt, map[int]string{1: node1Key, 2: node2Key})
	if err != nil {
		return nil, err
	}
	// The frontend claims to be every party in turn, signing with the only key
	// it has.
	forged, err := signAll(stmt, map[int]string{1: rogueKey, 2: rogueKey, 3: rogueKey})
	if err != nil {
		return nil, err
	}
	one, err := attest.Sign(node1Key, 1, stmt)
	if err != nil {
		return nil, err
	}
	replayed := []jsonAttestation{
		{PartyID: 1, Signature: hex.EncodeToString(one.Signature)},
		{PartyID: 2, Signature: hex.EncodeToString(one.Signature)},
		{PartyID: 3, Signature: hex.EncodeToString(one.Signature)},
	}
	// Node 1's key configured under party 2 as well, and node 1 signing under
	// both ids: a copy-paste in a config file that lets one host satisfy 2-of-3.
	selfSigned, err := signAll(stmt, map[int]string{1: node1Key, 2: node1Key})
	if err != nil {
		return nil, err
	}

	mutations := []namedStatement{
		{Name: "wallet id", Statement: toJSON(with(stmt, func(s *attest.Statement) { s.WalletID = "bridge-other" }))},
		{Name: "address", Statement: toJSON(with(stmt, func(s *attest.Statement) {
			s.Address = "0x1111111111111111111111111111111111111111"
		}))},
		{Name: "group key", Statement: toJSON(with(stmt, func(s *attest.Statement) {
			other := append([]byte(nil), groupPub...)
			other[32] ^= 0x01
			s.GroupPub = other
		}))},
		{Name: "threshold", Statement: toJSON(with(stmt, func(s *attest.Statement) { s.Threshold = 3 }))},
		{Name: "party set", Statement: toJSON(with(stmt, func(s *attest.Statement) { s.AllIDs = []int{1, 2, 4} }))},
		{Name: "party count", Statement: toJSON(with(stmt, func(s *attest.Statement) { s.AllIDs = []int{1, 2} }))},
	}

	out := fixtures{
		Note: "Generated by `go run ./client-ts/test/gen-fixtures` from the Go attest package. " +
			"Do not hand-edit: these bytes are what the TypeScript implementation is checked against.",
		Statement:         toJSON(stmt),
		Digest:            hex.EncodeToString(digest[:]),
		Nodes:             nodes,
		Threshold:         2,
		Genuine:           genuine,
		Forged:            forged,
		Replayed:          replayed,
		MutatedStatements: mutations,
		ReorderedIDs:      toJSON(with(stmt, func(s *attest.Statement) { s.AllIDs = []int{3, 1, 2} })),
		DuplicateKeyNodes: []jsonNodeKey{
			{PartyID: 1, PubKey: pubOf(node1Key)},
			{PartyID: 2, PubKey: pubOf(node1Key)},
			{PartyID: 3, PubKey: pubOf(node3Key)},
		},
		SelfSignedUnderTwoIDs: selfSigned,
	}

	// Sanity-check the fixtures against the implementation that produced them,
	// so a broken generator cannot ship a file the TypeScript side would happily
	// agree with.
	if err := selfCheck(stmt, out); err != nil {
		return nil, err
	}

	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(blob, '\n'), nil
}

func selfCheck(stmt attest.Statement, f fixtures) error {
	nodes := toNodeKeys(f.Nodes)
	if err := attest.Verify(stmt, toAttestations(f.Genuine), nodes, f.Threshold); err != nil {
		return fmt.Errorf("genuine attestations do not verify: %w", err)
	}
	for name, bad := range map[string][]jsonAttestation{
		"forged":   f.Forged,
		"replayed": f.Replayed,
	} {
		if err := attest.Verify(stmt, toAttestations(bad), nodes, f.Threshold); err == nil {
			return fmt.Errorf("%s attestations verified", name)
		}
	}
	for _, m := range f.MutatedStatements {
		if err := attest.Verify(fromJSON(m.Statement), toAttestations(f.Genuine), nodes, f.Threshold); err == nil {
			return fmt.Errorf("mutated statement %q verified", m.Name)
		}
	}
	if err := attest.Verify(stmt, toAttestations(f.SelfSignedUnderTwoIDs), toNodeKeys(f.DuplicateKeyNodes), f.Threshold); err == nil {
		return fmt.Errorf("one node satisfied the threshold under two party ids")
	}
	return nil
}

func with(s attest.Statement, mutate func(*attest.Statement)) attest.Statement {
	c := s
	c.AllIDs = append([]int(nil), s.AllIDs...)
	c.GroupPub = append([]byte(nil), s.GroupPub...)
	mutate(&c)
	return c
}

func signAll(s attest.Statement, keys map[int]string) ([]jsonAttestation, error) {
	ids := make([]int, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	// Sorted so the fixture file does not churn with map iteration order.
	sort.Ints(ids)
	out := make([]jsonAttestation, 0, len(keys))
	for _, id := range ids {
		a, err := attest.Sign(keys[id], id, s)
		if err != nil {
			return nil, err
		}
		out = append(out, jsonAttestation{PartyID: id, Signature: hex.EncodeToString(a.Signature)})
	}
	return out, nil
}

func pubOf(privHex string) string {
	key, err := crypto.HexToECDSA(privHex)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))
}

func toJSON(s attest.Statement) jsonStatement {
	return jsonStatement{
		WalletID:    s.WalletID,
		Address:     s.Address,
		GroupPubkey: hex.EncodeToString(s.GroupPub),
		Threshold:   s.Threshold,
		AllIDs:      s.AllIDs,
	}
}

func fromJSON(s jsonStatement) attest.Statement {
	pub, err := hex.DecodeString(strings.TrimPrefix(s.GroupPubkey, "0x"))
	if err != nil {
		panic(err)
	}
	return attest.Statement{
		WalletID:  s.WalletID,
		Address:   s.Address,
		GroupPub:  pub,
		Threshold: s.Threshold,
		AllIDs:    s.AllIDs,
	}
}

func toNodeKeys(in []jsonNodeKey) []attest.NodeKey {
	out := make([]attest.NodeKey, 0, len(in))
	for _, n := range in {
		pub, err := hex.DecodeString(n.PubKey)
		if err != nil {
			panic(err)
		}
		out = append(out, attest.NodeKey{PartyID: n.PartyID, PubKey: pub})
	}
	return out
}

func toAttestations(in []jsonAttestation) []*attest.Attestation {
	out := make([]*attest.Attestation, 0, len(in))
	for _, a := range in {
		sig, err := hex.DecodeString(a.Signature)
		if err != nil {
			panic(err)
		}
		out = append(out, &attest.Attestation{PartyID: a.PartyID, Signature: sig})
	}
	return out
}
