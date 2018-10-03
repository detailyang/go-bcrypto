// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// Package secp256k1 wraps the bitcoin secp256k1 C library.
package secp256k1

/*
#cgo CFLAGS: -I./libsecp256k1
#cgo CFLAGS: -I./libsecp256k1/src/
#define USE_NUM_NONE
#define USE_FIELD_10X26
#define USE_FIELD_INV_BUILTIN
#define USE_SCALAR_8X32
#define USE_SCALAR_INV_BUILTIN
#define NDEBUG
#include "./libsecp256k1/src/secp256k1.c"
#include "./libsecp256k1/src/modules/recovery/main_impl.h"
#include "ext.h"

typedef void (*callbackFunc) (const char* msg, void* data);
extern void secp256k1GoPanicIllegal(const char* msg, void* data);
extern void secp256k1GoPanicError(const char* msg, void* data);

static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        pos += lenbyte;
    }

    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;
    pos += slen;

    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}
*/
import "C"

import (
	"unsafe"
)

var context *C.secp256k1_context

func init() {
	// around 20 ms on a modern CPU.
	context = C.secp256k1_context_create_sign_verify()
	C.secp256k1_context_set_illegal_callback(context, C.callbackFunc(C.secp256k1GoPanicIllegal), nil)
	C.secp256k1_context_set_error_callback(context, C.callbackFunc(C.secp256k1GoPanicError), nil)
}

func CheckLowS(sig []byte) bool {
	csig, ok := parseSignatureFromBytes(sig)
	if !ok {
		return false
	}

	return C.secp256k1_ecdsa_signature_normalize(context, nil, csig) == cInt(0)
}

func VerifySignature(pubkey, msg, sig []byte) bool {
	csig, ok := parseSignatureFromBytes(sig)
	if !ok {
		return false
	}

	var cpubkey C.secp256k1_pubkey
	rv := C.secp256k1_ec_pubkey_parse(
		context,
		&cpubkey,
		cBuf(pubkey),
		cUlong(uint(len(pubkey))),
	)
	if rv == cInt(0) {
		return false
	}

	/**
	 * libsecp256k1's ECDSA verification requires lower-S signatures, which have
	 * not historically been enforced in Bitcoin, so normalize them first.
	 */
	C.secp256k1_ecdsa_signature_normalize(context, csig, csig)
	return C.secp256k1_ecdsa_verify(context, csig, cBuf(msg), &cpubkey) == cInt(1)
}

func Signature(msg []byte, privatekey []byte, testCase uint32) ([]byte, bool) {
	var (
		noncefunc = C.secp256k1_nonce_function_rfc6979
		sig       C.secp256k1_ecdsa_signature
	)

	var rv C.int

	if testCase > 0 {
		nonce := uint32(testCase)
		rv = C.secp256k1_ecdsa_sign(
			context,
			&sig,
			cBuf(msg),
			cBuf(privatekey),
			noncefunc,
			unsafe.Pointer(&nonce))
	} else {
		rv = C.secp256k1_ecdsa_sign(
			context,
			&sig,
			cBuf(msg),
			cBuf(privatekey),
			noncefunc,
			nil)
	}

	if rv == cInt(0) {
		return nil, false
	}

	nsig := 72
	sigBuf := make([]byte, nsig)

	rv = C.secp256k1_ecdsa_signature_serialize_der(
		context,
		cBuf(sigBuf),
		(*C.ulong)(unsafe.Pointer(&nsig)),
		&sig,
	)

	return C.GoBytes(unsafe.Pointer(&sigBuf[0]), cInt(nsig)), rv == C.int(1)
}

func CreatePubkeyFromBytes(privatekey []byte, compressed bool) ([]byte, bool) {
	pubkey := &C.secp256k1_pubkey{}
	success := C.secp256k1_ec_pubkey_create(
		context,
		pubkey,
		cBuf(privatekey[:]))
	if success != C.int(1) {
		return nil, false
	}

	flags := uint(C.SECP256K1_EC_UNCOMPRESSED)
	if compressed {
		flags = C.SECP256K1_EC_COMPRESSED
	}

	buflen := 65
	buf := make([]byte, buflen)

	success = C.secp256k1_ec_pubkey_serialize(
		context,
		cBuf(buf[:]),
		(*C.ulong)(unsafe.Pointer(&buflen)),
		pubkey,
		(C.uint)(flags),
	)

	return C.GoBytes(unsafe.Pointer(&buf[0]), (C.int)(buflen)), success == C.int(1)
}

func parseSignatureFromBytes(data []byte) (*C.secp256k1_ecdsa_signature, bool) {
	if len(data) == 0 {
		return nil, false
	}

	sig := &C.secp256k1_ecdsa_signature{}
	ret := C.ecdsa_signature_parse_der_lax(
		context,
		sig,
		(*C.uchar)(unsafe.Pointer(&data[0])),
		(C.size_t)(len(data)),
	)

	if ret != C.int(1) {
		return nil, false
	}

	return sig, true
}

func cUlong(n uint) C.ulong {
	return (C.ulong)(n)
}

func cInt(n int) C.int {
	return (C.int)(n)
}

func cUint(n uint) C.uint {
	return (C.uint)(n)
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}
