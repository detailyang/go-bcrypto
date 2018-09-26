package bcrypto

import (
	. "github.com/detailyang/go-bprimitives"
)

type AddressType int
type Network int

const (
	AddressP2PKH AddressType = iota
	AddressP2SH
)

const (
	Mainet Network = iota
	Testnet
)

// https://en.bitcoin.it/wiki/Address
type Address struct {
	Kind    AddressType
	Network Network
	Hash    Hash
}

func NewAddress(kind AddressType, network Network, hash Hash) *Address {
	return &Address{
		Kind:    kind,
		Network: network,
		Hash:    hash,
	}
}

// func (a Address) GeneratePrivateKey()

// func (a *Address) String() string {

// }
