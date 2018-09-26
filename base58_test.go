package bcrypto

import (
	"bytes"
	"crypto/rand"
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

func TestBase58Decode(t *testing.T) {
	tests := []struct {
		expect []byte
		input  string
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
		rv, err := bigintBase58Decode(test.input)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(rv, test.expect) {
			t.Errorf("expect %x got %x", test.expect, rv)
		}
	}
}

func TestBase58EncodeAndDecode(t *testing.T) {
	buf := make([]byte, 128)
	for i := 0; i < 128; i++ {
		_, err := rand.Read(buf)
		if err != nil {
			t.Fatal(err)
		}

		data, err := bigintBase58Decode(bigintBase58Encode(buf))
		if !bytes.Equal(buf, data) {
			t.Fatalf("expect %x got %x", buf, data)
		}
	}

	zerobuf := make([]byte, 128)
	for i := 0; i < 128; i++ {
		_, err := rand.Read(zerobuf[8:])
		if err != nil {
			t.Fatal(err)
		}

		data, err := bigintBase58Decode(bigintBase58Encode(zerobuf))
		if !bytes.Equal(zerobuf, data) {
			t.Fatalf("expect %x got %x", zerobuf, data)
		}
	}
}
