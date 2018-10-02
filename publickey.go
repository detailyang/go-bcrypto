package bcrypto

import "encoding/hex"

type PublicKey []byte

func NewPublicKey(d []byte) PublicKey {
	return PublicKey(d)
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

func (p PublicKey) Hex() string {
	return hex.EncodeToString(p)
}

func (p PublicKey) String() string {
	return p.Hex()
}

func (p PublicKey) Bytes() []byte {
	return p
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
