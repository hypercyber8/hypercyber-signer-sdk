package owner

import (
	"crypto/ed25519"
	"testing"
)

func TestBindingAuthenticatesAllIdentityFields(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{WalletID: "trading-global-pool-slot-1", Address: "0x1111111111111111111111111111111111111111", OwnerAddress: "0x2222222222222222222222222222222222222222", Network: "Mainnet"}
	if err := b.Sign(private); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(public); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Binding){
		func(b *Binding) { b.WalletID += "0" },
		func(b *Binding) { b.Address = b.OwnerAddress },
		func(b *Binding) { b.OwnerAddress = "0x3333333333333333333333333333333333333333" },
		func(b *Binding) { b.Network = "Testnet" },
	} {
		changed := b
		change(&changed)
		if changed.Verify(public) == nil {
			t.Fatal("accepted modified binding")
		}
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if b.Verify(other) == nil {
		t.Fatal("accepted another authority")
	}
}
