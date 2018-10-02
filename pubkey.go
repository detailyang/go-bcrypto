package bcrypto

import (
	"encoding/hex"
	"errors"

	secp256k1 "github.com/detailyang/go-bcrypto/secp256k1"
)

var (
	ErrPubkeyParseFailed = errors.New("pubkey: parse failed")
)

type Pubkey struct {
	PK         *secp256k1.PublicKey
	Compressed bool
}

// func NewPubkey()

func NewPubkeyFromBytes(data []byte) (*Pubkey, error) {
	pubkey, ok := secp256k1.PubkeyParse(data)
	if !ok {
		return nil, ErrPubkeyParseFailed
	}

	return &Pubkey{
		PK:         pubkey,
		Compressed: isCompressed(data),
	}, nil
}

func (p *Pubkey) Hex() string {
	return hex.EncodeToString((p.PK.Get()))
}

func (p *Pubkey) String() string {
	return p.Hex()
}

func (p *Pubkey) IsCompressed() bool {
	return isCompressed(p.PK.Get())
}

func isCompressed(bytes []byte) bool {
	if len(bytes) != 33 {
		return false
	}

	if bytes[0] != 0x02 && bytes[0] != 0x03 {
		return false
	}

	return true
}
