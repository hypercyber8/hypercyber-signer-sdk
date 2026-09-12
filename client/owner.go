package client

import (
	"context"

	"github.com/hypercyber8/hypercyber-signer-sdk/owner"
	vaultv1 "github.com/hypercyber8/hypercyber-signer-sdk/proto/vault/v1"
)

// OwnerBinder is intentionally separate from the signing Client interface.
// Only a credential explicitly granted BindWalletOwner may use it.
type OwnerBinder interface {
	BindWalletOwner(context.Context, owner.Binding) error
}

func (c *client) BindWalletOwner(ctx context.Context, b owner.Binding) error {
	_, err := c.rpc.BindWalletOwner(ctx, &vaultv1.BindWalletOwnerRequest{
		WalletId: b.WalletID, Address: b.Address, OwnerAddress: b.OwnerAddress,
		Network: b.Network, AuthoritySignature: b.Signature,
	})
	return err
}
