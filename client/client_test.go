package client

import (
	"context"
	"crypto/tls"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc"

	"github.com/hypercyber8/hypercyber-signer-sdk/attest"
	vaultv1 "github.com/hypercyber8/hypercyber-signer-sdk/proto/vault/v1"
)

type recordingVaultServiceClient struct {
	vaultv1.VaultServiceClient
	req *vaultv1.TypedDataByWalletRequest
}

func (c *recordingVaultServiceClient) TypedDataByWallet(_ context.Context, req *vaultv1.TypedDataByWalletRequest, _ ...grpc.CallOption) (*vaultv1.RSVResponse, error) {
	c.req = req
	return &vaultv1.RSVResponse{R: []byte{1}, S: []byte{2}, V: 27}, nil
}

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

func TestClientCertificateMustHaveMatchingKey(t *testing.T) {
	for _, opt := range []Option{
		WithClientCertificate("client.crt", ""),
		WithClientCertificate("", "client.key"),
	} {
		c, err := New(context.Background(), "127.0.0.1:0", opt)
		if err == nil {
			c.Close()
			t.Fatal("New accepted a partial client certificate identity")
		}
	}
}

func TestClientCertificateCannotUsePlaintextTransport(t *testing.T) {
	c, err := New(context.Background(), "127.0.0.1:0", WithInsecure(),
		WithClientCertificate("client.crt", "client.key"))
	if err == nil {
		c.Close()
		t.Fatal("New accepted a client certificate with insecure transport")
	}
}

func TestClientCertificateRequiresBearerSecondFactor(t *testing.T) {
	c, err := New(context.Background(), "127.0.0.1:0",
		WithClientCertificate("client.crt", "client.key"))
	if err == nil {
		c.Close()
		t.Fatal("New accepted mutual TLS without the bearer-token second factor")
	}
}

func TestTLSRequiresVersion13(t *testing.T) {
	cfg, err := tlsConfig(&options{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion=%x, want TLS 1.3", cfg.MinVersion)
	}
}

func TestTypedDataWithActionByWalletCarriesTheWalletID(t *testing.T) {
	rpc := &recordingVaultServiceClient{}
	c := &client{rpc: rpc}
	expires := uint64(99)
	result, err := c.TypedDataWithActionByWallet(
		context.Background(), "request-1", "trading-global-pool-slot-007", "hyperliquid",
		big.NewInt(42161), []byte{1}, []byte{2}, &HyperliquidAction{
			Msgpack: []byte{3}, Nonce: 4, VaultAddress: "0x5",
			ExpiresAfter: &expires, IsMainnet: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if rpc.req == nil || rpc.req.WalletId != "trading-global-pool-slot-007" {
		t.Fatalf("wallet ID request = %#v", rpc.req)
	}
	if len(rpc.req.Action.GetActionMsgpack()) != 1 || !rpc.req.Action.GetHasExpiresAfter() {
		t.Fatalf("structured action request = %#v", rpc.req.Action)
	}
	if result.R.Cmp(big.NewInt(1)) != 0 || result.S.Cmp(big.NewInt(2)) != 0 || result.V != 27 {
		t.Fatalf("result = %#v", result)
	}
}
