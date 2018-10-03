package bcrypto

import "github.com/detailyang/go-bcrypto/secp256k1"

func CheckLowS(sig []byte) bool {
	return secp256k1.CheckLowS(sig)
}
