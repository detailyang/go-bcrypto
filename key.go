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

//  ECDSA-Sig-Value ::= SEQUENCE {
// r INTEGER,
// s INTEGER }
// See https://tools.ietf.org/html/rfc3278#section-8.2
func (k *Key) Signature(msg []byte, testCase uint32) ([]byte, bool) {
	sig, ok := secp256k1.Signature(msg, k.Data, testCase)
	if !ok {
		return nil, false
	}

	return sig, true
}
