package bcrypto

import (
	"math/big"
)

const (
	alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var (
	big58 = big.NewInt(58)
	big0  = big.NewInt(0)
)

func Base58Encode(data []byte) string {
	return bigintBase58Encode(data)
}

/*
   code_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
   x = convert_bytes_to_big_integer(hash_result);

   output_string = "";

   while(x > 0)
   {
       (x, remainder) = divide(x, 58);
       output_string.append(code_string[remainder]);
   }

   repeat(number_of_leading_zero_bytes_in_hash)
   {
       output_string.append(code_string[0]);
   }

   output_string.reverse();
*/
func bigintBase58Encode(data []byte) string {
	b := new(big.Int).SetBytes(data)

	rv := make([]byte, 0, len(data)*137/100)

	for b.Cmp(big0) > 0 {
		mod := new(big.Int)
		b.DivMod(b, big58, mod)
		rv = append(rv, alphabet[mod.Int64()])
	}

	for _, v := range data {
		if v != 0 {
			break
		}
		rv = append(rv, alphabet[0])
	}

	n := len(rv)
	for i := 0; i < n/2; i++ {
		rv[i], rv[n-1-i] = rv[n-1-i], rv[i]
	}

	return string(rv)
}

// func bigintBase58Decode(str string) ([]byte, error) {

// }

func trezorBase58Encode(data []byte) string {
	ndata := len(data)
	zcount := 0

	for zcount < ndata && data[zcount] == 0 {
		zcount++
	}

	// log(256,2)/log(58,2)
	size := (ndata-zcount)*137/100 + 1
	high := size - 1
	j := size - 1
	i := zcount
	buf := make([]byte, size)

	for ; i < ndata; i++ {
		carry := uint32(data[i])
		j = size - 1

		for ; j > high || carry != 0; j-- {
			// b58 = b58 * 256 + ch
			carry += 256 * uint32(buf[j])
			buf[j] = byte(carry % 58)
			carry /= 58
		}

		high = j
	}

	for j = 0; j < size && buf[j] == 0; j++ {
	}

	b58 := make([]byte, size-j+zcount)

	for i = 0; j < size; i++ {
		if i < zcount {
			b58[i] = alphabet[0]
		} else {
			b58[i] = alphabet[buf[j]]
			j++
		}
	}

	return string(b58)
}
