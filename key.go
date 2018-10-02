package bcrypto

import (
	"errors"

	"github.com/detailyang/go-bcrypto/secp256k1"
)

type Key struct {
	Data       []byte
	Compressed bool
}

func NewKey(k []byte, compressed bool) *Key {
	return &Key{
		Data:       k,
		Compressed: compressed,
	}
}

func (k *Key) GetPubkey() (PublicKey, error) {
	pubkey, ok := secp256k1.CreatePubkeyFromBytes(k.Data, k.Compressed)
	if !ok {
		return nil, errors.New("create pubkey failed")
	}

	return NewPublicKey(pubkey), nil
}
