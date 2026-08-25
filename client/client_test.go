package client

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/hypercyber8/hypercyber-signer-sdk/attest"
)

func testNodeKey(t *testing.T, partyID int) attest.NodeKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return attest.NodeKey{PartyID: partyID, PubKey: crypto.CompressPubkey(&key.PublicKey)}
}

// WithNodeKeys and no keys must fail closed. Silently leaving verification off
// would hand back a client that reports Attested=false and creates wallets
// anyway — a caller that asked to be protected, believes it is, and is not.
func TestWithNodeKeysWithoutKeysIsRefused(t *testing.T) {
	c, err := New(context.Background(), "127.0.0.1:0", WithInsecure(), WithNodeKeys(2))
	if err == nil {
		c.Close()
		t.Fatal("New accepted WithNodeKeys with no keys, silently disabling verification")
	}
}

// The same misconfiguration that lets one node meet the threshold alone must be
// caught when the client is built, not on the first wallet it creates.
func TestDuplicateNodeKeysAreRefusedAtConstruction(t *testing.T) {
	n1 := testNodeKey(t, 1)
	dup := attest.NodeKey{PartyID: 2, PubKey: n1.PubKey}

	c, err := New(context.Background(), "127.0.0.1:0", WithInsecure(), WithNodeKeys(2, n1, dup))
	if err == nil {
		c.Close()
		t.Fatal("New accepted one public key configured under two party ids")
	}
}

// The honest configuration still works, so the checks above are rejecting the
// mistake and not the feature.
func TestDistinctNodeKeysAreAccepted(t *testing.T) {
	c, err := New(context.Background(), "127.0.0.1:0", WithInsecure(),
		WithNodeKeys(2, testNodeKey(t, 1), testNodeKey(t, 2), testNodeKey(t, 3)))
	if err != nil {
		t.Fatalf("a well-formed node key set was rejected: %v", err)
	}
	defer c.Close()
	if got := len(c.(*client).opts.nodeKeys); got != 3 {
		t.Fatalf("configured node keys = %d, want 3", got)
	}
}

// No WithNodeKeys at all remains legal: the single-host deployment has nothing
// independent to attest, and Create then returns Attested=false rather than
// failing.
func TestNoNodeKeysStillBuilds(t *testing.T) {
	c, err := New(context.Background(), "127.0.0.1:0", WithInsecure())
	if err != nil {
		t.Fatalf("client without node keys was rejected: %v", err)
	}
	c.Close()
}
