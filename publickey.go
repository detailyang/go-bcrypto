package bcrypto

import (
	"encoding/hex"

	"github.com/detailyang/go-bcrypto/secp256k1"
	. "github.com/detailyang/go-bprimitives"
)

type PublicKey []byte

func NewPublicKey(d []byte) PublicKey {
	return PublicKey(d)
}

func (p PublicKey) Verify(msg, sig []byte) bool {
	return secp256k1.VerifySignature(p, msg, sig)
}

func (p PublicKey) Length() int {
	if p[0] == 2 || p[0] == 3 {
		return 33
	}

	if p[0] == 4 || p[0] == 6 || p[0] == 7 {
		return 65
	}

	return 0
}

func (p PublicKey) ID() []byte {
	return Hash160(p.Bytes())
}

func (p PublicKey) Hex() string {
	return hex.EncodeToString(p)
}

func (p PublicKey) String() string {
	return p.Hex()
}

func (p PublicKey) Clone() PublicKey {
	data := make([]byte, len(p))
	copy(data, p)
	return NewPublicKey(data)
}

func (p PublicKey) Bytes() []byte {
	return p.Clone()
}

func (p PublicKey) IsCompressed() bool {
	if len(p) != 33 {
		return false
	}

	if p[0] != 0x02 && p[0] != 0x03 {
		return false
	}

	return true
}
