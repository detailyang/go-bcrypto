package bcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"

	. "github.com/detailyang/go-bprimitives"
)

var (
	ErrPrivateBadFormat   = errors.New("bad private format")
	ErrPrivateBadNetwork  = errors.New("bad private network")
	ErrPrivateBadChecksum = errors.New("bad private checksum")
)

type PrivateKey struct {
	Network    Network
	Secret     Hash
	Compressed bool
}

func NewPrivateKeyFromHash(network Network, secret Hash, compressed bool) *PrivateKey {
	return &PrivateKey{
		Network:    network,
		Secret:     secret,
		Compressed: compressed,
	}
}

func NewPrivateKeyFromHexString(hexstring string) (*PrivateKey, error) {
	data, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromBytes(data)
}

func NewPrivateKeyFromBytes(data []byte) (*PrivateKey, error) {
	compressed := false
	ndata := len(data)

	if ndata == 38 {
		compressed = true
	} else if ndata == 37 {
		compressed = false
	} else {
		return nil, ErrPrivateBadFormat
	}

	if compressed && data[data[ndata-5]] != 1 {
		return nil, ErrPrivateBadFormat
	}

	buffer := NewReadBuffer(data)
	network, err := buffer.GetUint8()
	if err != nil {
		return nil, err
	}

	switch network {
	case 128:
		network = uint8(Mainet)
	case 239:
		network = uint8(Testnet)
	default:
		return nil, ErrPrivateBadNetwork
	}

	secret, err := buffer.GetHash()
	if err != nil {
		return nil, err
	}

	cs, err := buffer.GetBytes(4)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(DHash256(data[:ndata-4]).TakeBytes(0, 4), cs) {
		return nil, ErrPrivateBadFormat
	}

	return &PrivateKey{
		Network:    Network(network),
		Secret:     secret,
		Compressed: compressed,
	}, nil
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
		buffer.PutUint8(239)
	}

	buffer.PutHash(pk.Secret)

	if pk.Compressed {
		buffer.PutUint8(1)
	}

	return buffer.PutCheckSum(4).Bytes()
}

func (pk *PrivateKey) Bytes() []byte {
	return pk.Layout()
}

func (pk *PrivateKey) Base58() string {
	return Base58Encode(pk.Layout())
}

func (pk *PrivateKey) Hex() string {
	return hex.EncodeToString(pk.Layout())
}

func (pk *PrivateKey) String() string {
	return pk.Hex()
}
