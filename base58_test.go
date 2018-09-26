package bcrypto

import (
	"testing"
)

func TestBase58Encode(t *testing.T) {
	tests := []struct {
		input  []byte
		expect string
	}{
		{
			[]byte{}, "",
		},
		{
			[]byte{32}, "Z",
		},
		{
			[]byte{45}, "n",
		},
		{
			[]byte{48}, "q",
		},
		{
			[]byte{49}, "r",
		},
		{
			[]byte{57}, "z",
		},
		{
			[]byte{45, 49}, "4SU",
		},
		{
			[]byte{49, 49}, "4k8",
		},
	}

	for _, test := range tests {
		rv := bigintBase58Encode(test.input)
		if rv != test.expect {
			t.Errorf("expect %s got %s", test.expect, rv)
		}
	}

	for _, test := range tests {
		rv := trezorBase58Encode(test.input)
		if rv != test.expect {
			t.Errorf("expect %s got %s", test.expect, rv)
		}
	}
}
