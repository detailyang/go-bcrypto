package bcrypto

import (
	"testing"
)

func TestKey(t *testing.T) {
	var (
		key0bytes = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

		key1bytes = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}

		key2bytes = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}
	)

	key0 := NewKey(key0bytes[:], false)
	key0c := NewKey(key0bytes[:], true)
	pubkey0, _ := key0.GetPubkey()
	if pubkey0.String() != "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8" {
		t.Error("expect 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	}

	pubkey0c, _ := key0c.GetPubkey()
	if pubkey0c.String() != "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" {
		t.Error("expect 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	}

	key1 := NewKey(key1bytes[:], false)
	key1c := NewKey(key1bytes[:], true)
	pubkey1, _ := key1.GetPubkey()
	pubkey1c, _ := key1c.GetPubkey()
	if pubkey1.String() != "048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf" {
		t.Error("expect 048282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f5150811f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf")
	}
	if pubkey1c.String() != "038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508" {
		t.Error("expect 038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508")
	}

	key2 := NewKey(key2bytes[:], false)
	key2c := NewKey(key2bytes[:], true)
	pubkey2, _ := key2.GetPubkey()
	pubkey2c, _ := key2c.GetPubkey()

	if pubkey2.String() != "04363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff464004e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9" {
		t.Error("expect 04363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff464004e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9")
	}

	if pubkey2c.String() != "03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640" {
		t.Error("expect 03363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640")
	}
}
