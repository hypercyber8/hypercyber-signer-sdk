package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/hypercyber8/hypercyber-signer-sdk/attest"
	vaultv1 "github.com/hypercyber8/hypercyber-signer-sdk/proto/vault/v1"
)

// WalletCreateResult is returned by Create.
type WalletCreateResult struct {
	WalletID    string
	ECDSAPubKey string
	// Attested reports whether at least `threshold` distinct signer nodes proved
	// they hold a share of this wallet.
	//
	// On a distributed deployment this is the difference between an address the
	// vault says is threshold-backed and one it has PROVEN is: a compromised
	// frontend can skip the ceremony, generate a key it alone knows, and return
	// that address. Configure WithNodeKeys and Create refuses an unattested
	// wallet outright; without it, this stays false and the caller is trusting
	// the frontend's word.
	Attested bool
}

// Wallet describes the public identity and threshold topology of an existing
// wallet. It contains no share or other secret material.
type Wallet struct {
	WalletID    string
	Markup      string
	Address     string
	GroupPubKey []byte
	Threshold   int
	AllIDs      []int
}

// HyperliquidAction describes the L1 action a TypedData request is signing.
//
// Msgpack must be the bytes the Hyperliquid SDK itself produced —
// hyperliquid.EncodeAction — not a re-encoding. The vault checks that these
// exact bytes derive the domain separator and typed-data hash in the same
// request, so the description and the signature pre-image are the same thing and
// a caller cannot describe one action while another gets signed. Bytes from a
// different encoder would fail that check, and would in any case not match the
// body the SDK sends, which the exchange would reject.
type HyperliquidAction struct {
	Msgpack      []byte
	Nonce        uint64
	VaultAddress string
	ExpiresAfter *uint64
	IsMainnet    bool
}

// RSVResult is returned by TypedData.
type RSVResult struct {
	R *big.Int
	S *big.Int
	V int
}

// Client is a gRPC client for the vault signing API. Every wallet uses
// threshold ECDSA; there is no custody model to select.
type Client interface {
	Create(ctx context.Context, markup, walletID string) (*WalletCreateResult, error)
	GetWallet(ctx context.Context, walletID string) (*Wallet, error)
	Sign(ctx context.Context, requestID, address, network string, chainID *big.Int, tx []byte) ([]byte, error)
	SignByWallet(ctx context.Context, requestID, walletID, network string, chainID *big.Int, tx []byte) ([]byte, error)
	TypedData(ctx context.Context, requestID string, address common.Address, network string, chainID *big.Int, ds, tdh []byte) (*RSVResult, error)
	// TypedDataWithAction is TypedData plus a description of WHAT is being
	// signed, so the vault can authorize the action rather than only sign its
	// hash. Prefer it wherever the action is available; see HyperliquidAction.
	TypedDataWithAction(ctx context.Context, requestID string, address common.Address, network string, chainID *big.Int, ds, tdh []byte, action *HyperliquidAction) (*RSVResult, error)
	// TypedDataByWallet selects the signer by its durable wallet ID. Prefer it
	// when the caller already has an authoritative wallet identity.
	TypedDataByWallet(ctx context.Context, requestID, walletID, network string, chainID *big.Int, ds, tdh []byte) (*RSVResult, error)
	// TypedDataWithActionByWallet is TypedDataByWallet plus the structured
	// Hyperliquid action the signature authorizes.
	TypedDataWithActionByWallet(ctx context.Context, requestID, walletID, network string, chainID *big.Int, ds, tdh []byte, action *HyperliquidAction) (*RSVResult, error)
	Close()
}

// Option configures the client.
type Option func(*options)

type options struct {
	secret         string
	isInsecure     bool
	caCertFile     string
	clientCertFile string
	clientKeyFile  string
	nodeKeys       []attest.NodeKey
	threshold      int
	// optErr carries an option's own validation failure to New, which is the
	// first place that can report one — an Option returns nothing.
	optErr error
}

func tlsConfig(o *options) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if o.caCertFile != "" {
		pemBytes, err := os.ReadFile(o.caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA cert: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("failed to load CA cert: %q contains no usable certificates", o.caCertFile)
		}
		config.RootCAs = roots
	}
	if o.clientCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(o.clientCertFile, o.clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

// WithNodeKeys enables verification of wallet attestations, and makes Create
// FAIL when a new wallet is not backed by `threshold` distinct signer nodes.
//
// The public keys must be learned out of band — from the operator, from
// configuration, from anywhere other than the vault being checked. A client that
// took them from the same response it is verifying would be asking the vault
// whether the vault is honest.
//
// Without this, Create still works and returns Attested=false. That is a
// deliberate default for the single-host deployment, which has nothing
// independent to attest; on a distributed one, not configuring it throws away
// the guarantee.
//
// Passing no keys — or keys that cannot carry a threshold, such as two party ids
// sharing one public key — is an error from New, not a quiet fall back to the
// unverified default. Silently disabling verification for a caller that asked
// for it is the worst outcome available: not asking leaves you knowing you are
// trusting the frontend, while asking and getting nothing leaves you certain of
// a guarantee you do not have.
func WithNodeKeys(threshold int, keys ...attest.NodeKey) Option {
	return func(o *options) {
		o.threshold = threshold
		if len(keys) == 0 {
			o.optErr = errors.New("client: WithNodeKeys was given no node keys, " +
				"which would disable the attestation verification it was called to enable")
			return
		}
		o.nodeKeys = append(o.nodeKeys, keys...)
	}
}

// WithSecret sets the authentication secret sent via metadata.
func WithSecret(secret string) Option {
	return func(o *options) {
		o.secret = secret
	}
}

// WithInsecure disables TLS. Only use for local development.
func WithInsecure() Option {
	return func(o *options) {
		o.isInsecure = true
	}
}

// WithCACert configures TLS with a custom CA certificate file (e.g. for self-signed certs).
func WithCACert(caCertFile string) Option {
	return func(o *options) {
		o.caCertFile = caCertFile
	}
}

// WithClientCertificate configures the caller identity presented during the
// TLS handshake. Production callers should use a distinct certificate/key pair
// per least-privilege credential and combine this with WithSecret: the vault
// binds the certificate to that credential and requires both factors when
// client certificate enforcement is enabled.
func WithClientCertificate(certFile, keyFile string) Option {
	return func(o *options) {
		o.clientCertFile = certFile
		o.clientKeyFile = keyFile
	}
}

// New dials the vault gRPC endpoint and returns a Client.
func New(_ context.Context, endpoint string, opts ...Option) (Client, error) {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	if o.optErr != nil {
		return nil, o.optErr
	}
	if (o.clientCertFile == "") != (o.clientKeyFile == "") {
		return nil, errors.New("client: client certificate and key must be configured together")
	}
	if o.isInsecure && o.clientCertFile != "" {
		return nil, errors.New("client: a client certificate cannot be used with insecure transport")
	}
	if o.clientCertFile != "" && o.secret == "" {
		return nil, errors.New("client: mutual TLS also requires WithSecret as the second authentication factor")
	}
	// Check the configured identities here rather than only on the first Create:
	// a set that cannot carry a threshold — duplicate party ids, or one key under
	// two ids so a single node counts twice — is a deployment mistake, and it
	// should stop the process that made it instead of surfacing the day someone
	// creates a wallet.
	if len(o.nodeKeys) > 0 {
		if err := attest.ValidateNodeKeys(o.nodeKeys); err != nil {
			return nil, fmt.Errorf("client: node keys cannot verify an attestation: %w", err)
		}
	}

	var dialOpts []grpc.DialOption
	switch {
	case o.isInsecure:
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	default:
		config, err := tlsConfig(o)
		if err != nil {
			return nil, err
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	}
	if o.secret != "" {
		dialOpts = append(dialOpts, grpc.WithUnaryInterceptor(secretMetadataInterceptor(o.secret)))
	}

	conn, err := grpc.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}
	return &client{
		conn: conn,
		rpc:  vaultv1.NewVaultServiceClient(conn),
		opts: o,
	}, nil
}

type client struct {
	conn *grpc.ClientConn
	rpc  vaultv1.VaultServiceClient
	opts *options
}

func (c *client) Close() {
	c.conn.Close()
}

func chainIDToBytes(id *big.Int) []byte {
	if id == nil {
		return nil
	}
	return id.Bytes()
}

func (c *client) Create(ctx context.Context, markup, walletID string) (*WalletCreateResult, error) {
	resp, err := c.rpc.Create(ctx, &vaultv1.CreateRequest{
		Markup:   markup,
		WalletId: walletID,
	})
	if err != nil {
		return nil, err
	}
	out := &WalletCreateResult{
		WalletID:    resp.WalletId,
		ECDSAPubKey: resp.EcdsaPubkey,
	}
	if len(c.opts.nodeKeys) == 0 {
		return out, nil
	}

	// Verification is not advisory. A caller that configured node keys asked for
	// a wallet it can prove is threshold-backed, so an unprovable one is an
	// error — returning it with a flag to check would be a flag that gets
	// ignored, and the funds go to the address either way.
	atts := make([]*attest.Attestation, 0, len(resp.Attestations))
	for _, a := range resp.Attestations {
		atts = append(atts, &attest.Attestation{PartyID: int(a.PartyId), Signature: a.Signature})
	}
	stmt := attest.Statement{
		WalletID:  resp.WalletId,
		Address:   resp.EcdsaPubkey,
		GroupPub:  resp.GroupPubkey,
		Threshold: int(resp.Threshold),
		AllIDs:    int32sToInts(resp.AllIds),
	}
	// The client's own configured threshold wins over the one in the response:
	// letting the server choose how many attestations are enough would let a
	// compromised one choose "one".
	want := c.opts.threshold
	if want < 2 {
		want = 2
	}
	if err := attest.Verify(stmt, atts, c.opts.nodeKeys, want); err != nil {
		return nil, fmt.Errorf("refusing wallet %s: %w", resp.WalletId, err)
	}
	out.Attested = true
	return out, nil
}

func (c *client) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	resp, err := c.rpc.GetWallet(ctx, &vaultv1.GetWalletRequest{WalletId: walletID})
	if err != nil {
		return nil, err
	}
	return &Wallet{
		WalletID:    resp.WalletId,
		Markup:      resp.Markup,
		Address:     resp.Address,
		GroupPubKey: append([]byte(nil), resp.GroupPubkey...),
		Threshold:   int(resp.Threshold),
		AllIDs:      int32sToInts(resp.AllIds),
	}, nil
}

func int32sToInts(in []int32) []int {
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

func (c *client) Sign(ctx context.Context, requestID, address, network string, chainID *big.Int, tx []byte) ([]byte, error) {
	resp, err := c.rpc.SignByAddress(ctx, &vaultv1.SignByAddressRequest{
		Address:     address,
		RequestId:   requestID,
		Network:     network,
		ChainId:     chainIDToBytes(chainID),
		Transaction: tx,
	})
	if err != nil {
		return nil, err
	}
	return resp.SignedTransaction, nil
}

func (c *client) SignByWallet(ctx context.Context, requestID, walletID, network string, chainID *big.Int, tx []byte) ([]byte, error) {
	resp, err := c.rpc.SignByWallet(ctx, &vaultv1.SignByWalletRequest{
		WalletId:    walletID,
		RequestId:   requestID,
		Network:     network,
		ChainId:     chainIDToBytes(chainID),
		Transaction: tx,
	})
	if err != nil {
		return nil, err
	}
	return resp.SignedTransaction, nil
}

func (c *client) TypedData(ctx context.Context, requestID string, address common.Address, network string, chainID *big.Int, ds, tdh []byte) (*RSVResult, error) {
	return c.TypedDataWithAction(ctx, requestID, address, network, chainID, ds, tdh, nil)
}

func (c *client) TypedDataWithAction(ctx context.Context, requestID string, address common.Address, network string, chainID *big.Int, ds, tdh []byte, action *HyperliquidAction) (*RSVResult, error) {
	return c.typedData(ctx, requestID, address, network, chainID, ds, tdh, hyperliquidActionWire(action))
}

func (c *client) TypedDataByWallet(ctx context.Context, requestID, walletID, network string, chainID *big.Int, ds, tdh []byte) (*RSVResult, error) {
	return c.TypedDataWithActionByWallet(ctx, requestID, walletID, network, chainID, ds, tdh, nil)
}

func (c *client) TypedDataWithActionByWallet(ctx context.Context, requestID, walletID, network string, chainID *big.Int, ds, tdh []byte, action *HyperliquidAction) (*RSVResult, error) {
	resp, err := c.rpc.TypedDataByWallet(ctx, &vaultv1.TypedDataByWalletRequest{
		WalletId:        walletID,
		RequestId:       requestID,
		Network:         network,
		ChainId:         chainIDToBytes(chainID),
		DomainSeparator: ds,
		TypedDataHash:   tdh,
		Action:          hyperliquidActionWire(action),
	})
	return typedDataResult(resp, err)
}

func hyperliquidActionWire(action *HyperliquidAction) *vaultv1.HyperliquidAction {
	if action == nil {
		return nil
	}
	wire := &vaultv1.HyperliquidAction{
		ActionMsgpack: action.Msgpack,
		Nonce:         action.Nonce,
		VaultAddress:  action.VaultAddress,
		IsMainnet:     action.IsMainnet,
	}
	if action.ExpiresAfter != nil {
		wire.ExpiresAfter = *action.ExpiresAfter
		wire.HasExpiresAfter = true
	}
	return wire
}

func (c *client) typedData(ctx context.Context, requestID string, address common.Address, network string, chainID *big.Int, ds, tdh []byte, action *vaultv1.HyperliquidAction) (*RSVResult, error) {
	resp, err := c.rpc.TypedData(ctx, &vaultv1.TypedDataRequest{
		RequestId:       requestID,
		Network:         network,
		ChainId:         chainIDToBytes(chainID),
		Address:         address.Bytes(),
		DomainSeparator: ds,
		TypedDataHash:   tdh,
		Action:          action,
	})
	return typedDataResult(resp, err)
}

func typedDataResult(resp *vaultv1.RSVResponse, err error) (*RSVResult, error) {
	if err != nil {
		return nil, err
	}
	return &RSVResult{
		R: new(big.Int).SetBytes(resp.R),
		S: new(big.Int).SetBytes(resp.S),
		V: int(resp.V),
	}, nil
}

func secretMetadataInterceptor(secret string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-vault-secret", secret)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
