package bcrypto

import (
	. "github.com/detailyang/go-bprimitives"
)

type PrivateKey struct {
	Network    Network
	Secret     Hash
	Compressed bool
}

func NewPrivateKeyFromRandom(network Network, compressed bool) *PrivateKey {
	return &PrivateKey{
		Network:    network,
		Secret:     NewRandomHash(),
		Compressed: compressed,
	}
}

func (pk *PrivateKey) Layout() []byte {
	buffer := NewBuffer()
	if pk.Network == Mainet {
		buffer.PutUint8(128)
	} else {
		buffer.PutUint8(129)
	}

	buffer.PutBytes(pk.Secret.Bytes())

	if pk.Compressed {
		buffer.PutUint8(1)
	}

	return buffer.PutCheckSum().Bytes()
}

func (pk *PrivateKey) String() string {
	return ""
}
