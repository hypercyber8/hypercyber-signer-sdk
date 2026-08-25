// Package attest lets a client verify that the address it was handed is really
// backed by shares on t or more independent nodes.
//
// # The gap this closes
//
// Create used to return an address on the frontend's word alone. A compromised
// frontend could skip the ceremony entirely, generate a key it knows, hand out
// that address, and sign for it alone forever — the client funds a wallet whose
// threshold never existed. Distributed key generation makes that harder, because
// the honest path really does put one share on each host, but nothing FORCES the
// frontend down that path and nothing PROVES to the client that it went.
//
// # Why node identity keys, and not the wallet's own key
//
// A signature by the new wallet's group key proves nothing: whoever holds a
// solo key for that address can produce one too, which is exactly the attacker
// being guarded against. The attestation has to be signed by something the
// client already trusts and the frontend cannot mint — so each signer node holds
// a long-term identity key, and clients learn those public keys out of band.
//
// That out-of-band step is not incidental. It is what makes the guarantee real:
// the client is not asking the vault whether the vault is honest.
package attest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// domain separates this signature from every other use of a node key, so an
// attestation can never be replayed as some other kind of assertion.
const domain = "hypercyber-vault-wallet-attestation-v1"

// Statement is what a node asserts: that it holds a share of this wallet, that
// the wallet has this address and group key, and that the group has this shape.
type Statement struct {
	WalletID  string
	Address   string
	GroupPub  []byte
	Threshold int
	AllIDs    []int
}

// Digest is the 32 bytes a node signs.
//
// Every field is length-prefixed. Without that, ("ab","c") and ("a","bc") would
// hash identically, and an attacker who controlled two adjacent fields could
// move the boundary between them while keeping the signature valid.
func (s Statement) Digest() ([32]byte, error) {
	if s.WalletID == "" {
		return [32]byte{}, errors.New("attestation needs a wallet id")
	}
	if s.Address == "" {
		return [32]byte{}, errors.New("attestation needs an address")
	}
	if len(s.GroupPub) != 33 {
		return [32]byte{}, fmt.Errorf("attestation group key must be 33 compressed bytes, got %d", len(s.GroupPub))
	}
	if s.Threshold < 2 {
		return [32]byte{}, fmt.Errorf("attestation threshold %d is below 2", s.Threshold)
	}
	if len(s.AllIDs) < s.Threshold {
		return [32]byte{}, fmt.Errorf("attestation lists %d parties, below its own threshold %d", len(s.AllIDs), s.Threshold)
	}

	ids := append([]int(nil), s.AllIDs...)
	sort.Ints(ids)

	var buf []byte
	appendField := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		buf = append(buf, n[:]...)
		buf = append(buf, b...)
	}
	appendField([]byte(domain))
	appendField([]byte(s.WalletID))
	appendField([]byte(strings.ToLower(s.Address)))
	appendField(s.GroupPub)

	var t [4]byte
	binary.BigEndian.PutUint32(t[:], uint32(s.Threshold))
	buf = append(buf, t[:]...)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(ids)))
	buf = append(buf, count[:]...)
	for _, id := range ids {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(id))
		buf = append(buf, b[:]...)
	}

	var out [32]byte
	copy(out[:], crypto.Keccak256(buf))
	return out, nil
}

// Attestation is one node's signed Statement.
type Attestation struct {
	// PartyID names which node signed. It is a hint for matching against a
	// configured public key, and carries no authority on its own: verification
	// recovers the signer from the signature and compares.
	PartyID int
	// Signature is 65 bytes, secp256k1 recoverable, over Statement.Digest.
	Signature []byte
}

// Sign produces this node's attestation. privKey is the node's long-term
// identity key, which exists only to sign these — it holds no funds and is not
// a key share.
func Sign(privKeyHex string, partyID int, s Statement) (*Attestation, error) {
	key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.ToLower(privKeyHex), "0x"))
	if err != nil {
		return nil, fmt.Errorf("node identity key is not a valid secp256k1 private key: %w", err)
	}
	digest, err := s.Digest()
	if err != nil {
		return nil, err
	}
	sig, err := crypto.Sign(digest[:], key)
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}
	return &Attestation{PartyID: partyID, Signature: sig}, nil
}

// NodeKey is a signer node's identity, as a client knows it.
type NodeKey struct {
	PartyID int
	// PubKey is the 33-byte compressed public key, learned OUT OF BAND. A client
	// that took these from the same response it is verifying would be asking the
	// vault whether the vault is honest.
	PubKey []byte
}

// ValidateNodeKeys checks that a set of configured node identities can actually
// carry a threshold. Call it where the configuration is loaded, so a bad set is
// caught once at startup rather than per request; Verify calls it again anyway,
// because nothing it protects is optional.
//
// Distinct public keys are the load-bearing part. Verify counts distinct PARTY
// IDS, so if one key is configured under two ids — a copy-paste between config
// entries, which nothing else in the system would ever complain about — the node
// holding it can sign twice, be counted twice, and satisfy a 2-of-3 threshold on
// its own. The deployment looks healthy right up until that one node is
// compromised, at which point the threshold it was supposed to have never
// existed.
func ValidateNodeKeys(nodes []NodeKey) error {
	if len(nodes) == 0 {
		return errors.New("no node identity keys configured, so attestations cannot be verified; " +
			"a client that skips this is trusting the frontend's word for the address")
	}
	byParty := make(map[int][]byte, len(nodes))
	byPub := make(map[string]int, len(nodes))
	for _, n := range nodes {
		if len(n.PubKey) != 33 {
			return fmt.Errorf("node %d public key must be 33 compressed bytes, got %d", n.PartyID, len(n.PubKey))
		}
		if _, dup := byParty[n.PartyID]; dup {
			return fmt.Errorf("party %d is configured more than once; each party id must name one node", n.PartyID)
		}
		if other, dup := byPub[string(n.PubKey)]; dup {
			return fmt.Errorf("parties %d and %d are configured with the same public key, "+
				"so one node would satisfy the threshold by itself", other, n.PartyID)
		}
		byParty[n.PartyID] = n.PubKey
		byPub[string(n.PubKey)] = n.PartyID
	}
	return nil
}

// Verify checks that at least `threshold` DISTINCT configured nodes attested to
// this statement.
//
// Counting distinct parties is the whole point. A frontend that could replay one
// node's attestation, or sign several itself, would reproduce the failure this
// exists to detect — so each signature must recover to a different configured
// key, and a party that appears twice counts once.
func Verify(s Statement, attestations []*Attestation, nodes []NodeKey, threshold int) error {
	if threshold < 2 {
		return fmt.Errorf("attestation threshold %d is below 2", threshold)
	}
	// Counting distinct party ids only means something if the ids name distinct
	// keys, so the configuration is checked before it is counted with.
	if err := ValidateNodeKeys(nodes); err != nil {
		return err
	}
	digest, err := s.Digest()
	if err != nil {
		return err
	}

	byParty := make(map[int][]byte, len(nodes))
	for _, n := range nodes {
		byParty[n.PartyID] = n.PubKey
	}

	seen := make(map[int]bool, len(attestations))
	for _, a := range attestations {
		if a == nil || len(a.Signature) != 65 {
			continue
		}
		want, known := byParty[a.PartyID]
		if !known {
			// An attestation from a party the client does not know about proves
			// nothing; counting it would let the frontend invent signers.
			continue
		}
		recovered, err := crypto.SigToPub(digest[:], a.Signature)
		if err != nil {
			continue
		}
		if string(crypto.CompressPubkey(recovered)) != string(want) {
			continue
		}
		seen[a.PartyID] = true
	}

	if len(seen) < threshold {
		return fmt.Errorf("wallet %s carries %d valid node attestations, below its threshold of %d; "+
			"the address may not be backed by a real threshold sharing",
			s.Address, len(seen), threshold)
	}
	return nil
}
