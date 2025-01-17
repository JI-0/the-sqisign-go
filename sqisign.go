package sqisign

//#cgo CFLAGS: -I/usr/local/include -I/opt/local/include -I/usr/include -I/opt/homebrew/opt/gmp/include
//#cgo LDFLAGS: -L/usr/local/lib -L/opt/local/lib -L/usr/lib -L. -Lbuild/src -lsqisign_lvl1_nistapi
//#cgo LDFLAGS: -lsqisign_lvl1 -Lbuild/src/protocols/ref/lvl1 -lsqisign_protocols_lvl1 -Lbuild/src/precomp/ref/lvl1
//#cgo LDFLAGS: -lsqisign_precomp_lvl1 -Lbuild/src/klpt/ref/lvl1 -lsqisign_klpt_lvl1 -Lbuild/src/quaternion/ref/generic
//#cgo LDFLAGS: -lsqisign_quaternion_generic -Lbuild/src/id2iso/ref/lvl1 -lsqisign_id2iso_lvl1 -Lbuild/src/intbig/ref/generic
//#cgo LDFLAGS: -lsqisign_intbig_generic -Lbuild/src/gf/ref/lvl1 -lsqisign_gf_lvl1 -Lbuild/src/ec/ref/lvl1 -lsqisign_ec_lvl1
//#cgo LDFLAGS: -Lbuild/src/common/generic -lsqisign_common_sys -L/opt/homebrew/opt/gmp/lib -lgmp
//#include <stdlib.h>
//#include "sqisign-go.h"
import "C"
import (
	"crypto/rand"
	"unsafe"
)

const SecretKeyLen = 782
const PublicKeyLen = 64
const SignatureLen = 177

// func main() {
// 	pub, priv := SQIGenerateKeypair()

// 	fmt.Printf("%x\n\n", pub)
// 	fmt.Printf("%x\n\n", priv)

// 	sig := SQISign(string(priv), ("test"))

// 	fmt.Printf("%x\n\n", sig)
// 	fmt.Println(SQIVerify(string(pub), string(sig), ("test")))

// 	// fakeSig := sig
// 	// fakeSig[0] = byte(6)
// 	fmt.Println(SQIVerify(string(pub), string(sig), ("test1")))
// }

func SQIGenerateKeypair() ([]byte, []byte) {
	pub := C.CBytes(make([]byte, PublicKeyLen))
	defer C.free(unsafe.Pointer(pub))

	priv := C.CBytes(make([]byte, SecretKeyLen))
	defer C.free(unsafe.Pointer(priv))

	seedKey := make([]byte, 48)
	rand.Read(seedKey)
	seed := C.CString(string(seedKey))
	defer C.free(unsafe.Pointer(seed))

	if err := C.sqisigngo_gen_keypair(pub, priv, seed); int(err) != 0 {
		println(int(err))
	}

	return C.GoBytes(pub, PublicKeyLen), C.GoBytes(priv, SecretKeyLen)
}

func SQISign(priv, msg string) []byte {
	mlen := len([]byte(msg))

	sig := C.CBytes(make([]byte, SignatureLen+mlen))
	defer C.free(unsafe.Pointer(sig))

	privC := C.CString(priv)
	defer C.free(unsafe.Pointer(privC))

	msgC := C.CString(msg)
	defer C.free(unsafe.Pointer(msgC))

	_ = C.sqisigngo_sign(sig, msgC, privC) //; int(err) != 0 {
	// 	panic("error sqisigngo_sign")
	// }

	return C.GoBytes(sig, C.int(SignatureLen+mlen))[:SignatureLen]
}

func SQIVerify(pub, sig, msg string) bool {
	pubC := C.CString(pub)
	defer C.free(unsafe.Pointer(pubC))

	// sigB := append([]byte(sig), []byte(msg)...)
	sigC := C.CString(sig)
	defer C.free(unsafe.Pointer(sigC))

	msgC := C.CString(msg)
	defer C.free(unsafe.Pointer(msgC))

	return C.sqisigngo_verify(msgC, sigC, pubC) == 0
}
