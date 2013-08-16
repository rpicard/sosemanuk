package sosemanuk

// #include "sosemanuk.h"
import "C"

type sosemanuk struct {
    kc C.sosemanuk_key_context
    rc C.sosemanuk_run_context
    inited bool
}

const IVLenMin = 0
const IVLenMax = 16

const KeyLenMin = 1
const KeyLenMax = 32

// initialize a Sosemanuk stream cipher
func (s *sosemanuk) Init(key []byte, iv []byte) {
    // check key
    keylen := len(key)
    if keylen < KeyLenMin || keylen > KeyLenMax {
        panic("invalid key length")
    }

    // check iv
    ivlen := len(iv)
    if ivlen < IVLenMin || ivlen > IVLenMax {
        panic("invalid iv length")
    }
    var ivptr *C.uchar
    if ivlen > 0 {
        ivptr = (*C.uchar)(&iv[0])
    } else {
        ivptr = nil
    }

    // setup key schedule
    C.sosemanuk_schedule(&s.kc, (*C.uchar)(&key[0]), C.size_t(keylen))

    // init
    C.sosemanuk_init(&s.rc, &s.kc, ivptr, C.size_t(ivlen))

    // done
    s.inited = true
}

// fill output with random bytes
func (s *sosemanuk) PRNG(output []byte) []byte {
    if s == nil || !s.inited {
        panic("sosemanuk not Init() ed")
    }
    outputlen := len(output)
    if outputlen > 0 {
        C.sosemanuk_prng(&s.rc, (*C.uchar)(&output[0]), C.size_t(outputlen))
    }
    return output
}

// Do the stream cipher
func (s *sosemanuk) XORKeyStream(dst, src []byte) {
    if s == nil || !s.inited {
        panic("sosemanuk not Init() ed")
    }

    srclen := len(src)
    dstlen := len(dst)
    if dstlen < srclen {
        src = src[:dstlen]
        srclen = dstlen
    }
    if srclen == 0 {
        return
    }
    C.sosemanuk_encrypt(&s.rc, (*C.uchar)(&src[0]), (*C.uchar)(&dst[0]), C.size_t(srclen))
}
