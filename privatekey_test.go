package bcrypto

import (
	"testing"

	. "github.com/detailyang/go-bprimitives"
)

func TestPrivateKey(t *testing.T) {
	secret, err := NewHashFromReversedHexString("063377054c25f98bc538ac8dd2cf9064dd5d253a725ece0628a34e2f84803bd5")
	if err != nil {
		t.Fatal(err)
	}

	pk := NewPrivateKeyFromHash(Mainet, secret, false)

	if pk.Base58() != "5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu" {
		t.Errorf("expect %s got %s", "5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu", pk.String())
	}
}

func TestPrivateKeyFromBytes(t *testing.T) {
	data, _ := Base58Decode("5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu")
	pk, err := NewPrivateKeyFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	if pk.Base58() != "5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu" {
		t.Errorf("expect %s got %s", "5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu", pk.Base58())
	}
}
