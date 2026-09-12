// Package owner authenticates immutable copy-wallet ownership declarations.
package owner

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// Binding connects one durable MPC wallet to its permanent main wallet.
// Signature authenticates all fields with a separately provisioned authority.
type Binding struct {
	WalletID     string `json:"wallet_id"`
	Address      string `json:"address"`
	OwnerAddress string `json:"owner_address"`
	Network      string `json:"network"`
	Signature    []byte `json:"signature"`
}

// Message returns the canonical, domain-separated binding to authenticate.
func (b Binding) Message() ([]byte, error) {
	if !strings.HasPrefix(b.WalletID, "trading-global-pool-slot-") || len(b.WalletID) <= len("trading-global-pool-slot-") || len(b.WalletID) > 256 {
		return nil, errors.New("owner binding requires a trading pool wallet ID")
	}
	for _, address := range []string{b.Address, b.OwnerAddress} {
		if len(address) != 42 || !common.IsHexAddress(address) || address != strings.ToLower(address) || common.HexToAddress(address) == (common.Address{}) {
			return nil, errors.New("owner binding requires canonical nonzero addresses")
		}
	}
	if b.Address == b.OwnerAddress || (b.Network != "Mainnet" && b.Network != "Testnet") {
		return nil, errors.New("invalid owner binding network or self ownership")
	}
	return json.Marshal([]string{"hypercyber/wallet-owner/v1", b.WalletID, b.Address, b.OwnerAddress, b.Network})
}

// Sign authenticates a binding using the dedicated ownership authority key.
func (b *Binding) Sign(key ed25519.PrivateKey) error {
	if b == nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("owner binding signing key is unavailable")
	}
	message, err := b.Message()
	if err != nil {
		return err
	}
	b.Signature = ed25519.Sign(key, message)
	return nil
}

// Verify refuses bindings not authenticated by the configured authority.
func (b Binding) Verify(key ed25519.PublicKey) error {
	message, err := b.Message()
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, b.Signature) {
		return errors.New("owner binding authority signature is invalid")
	}
	return nil
}
