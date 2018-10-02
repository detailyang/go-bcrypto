package bcrypto

import (
	"github.com/detailyang/go-bcrypto/secp256k1"
)

type Signature secp256k1.ECDSASignature

func NewSignatureFromBytes(data []byte) (*Signature, error) {
	sig, ok := secp256k1.SignatureParseDer(data)
	if !ok {
		return nil, ErrPubkeyParseFailed
	}

	return (*Signature)(sig), nil
}

func (s *Signature) Verify(msg []byte, pubkey *Pubkey) bool {
	return secp256k1.VerifyECDSASignature((*secp256k1.ECDSASignature)(s), msg, pubkey.PK)
}
