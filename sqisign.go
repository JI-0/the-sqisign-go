package main

//#cgo CFLAGS: -I/usr/local/include -I/opt/local/include -I/usr/include -I/opt/homebrew/opt/gmp/include
//#cgo LDFLAGS: -L/usr/local/lib -L/opt/local/lib -L/usr/lib -Lbuilds/ref -L. -Lbuild/src -lsqisign_lvl1_nistapi
//#cgo LDFLAGS: -lsqisign_lvl1 -Lbuild/src/protocols/ref/lvl1 -lsqisign_protocols_lvl1 -Lbuild/src/precomp/ref/lvl1
//#cgo LDFLAGS: -lsqisign_precomp_lvl1 -Lbuild/src/klpt/ref/lvl1 -lsqisign_klpt_lvl1 -Lbuild/src/quaternion/ref/generic
//#cgo LDFLAGS: -lsqisign_quaternion_generic -Lbuild/src/id2iso/ref/lvl1 -lsqisign_id2iso_lvl1 -Lbuild/src/intbig/ref/generic
//#cgo LDFLAGS: -lsqisign_intbig_generic -Lbuild/src/gf/ref/lvl1 -lsqisign_gf_lvl1 -Lbuild/src/ec/ref/lvl1 -lsqisign_ec_lvl1
//#cgo LDFLAGS: -Lbuild/src/common/generic -lsqisign_common_sys -L/opt/homebrew/opt/gmp/lib -lgmp
//#include <stdlib.h>
//#include "sqisign-go.h"
import "C"
import (
	"fmt"
	"unsafe"
)

const SecretKeyLen = C.CRYPTO_SECRETKEYBYTES
const PublicKeyLen = C.CRYPTO_PUBLICKEYBYTES
const SignatureLen = C.CRYPTO_BYTES

func main() {
	pub := C.CBytes(make([]byte, PublicKeyLen))
	defer C.free(unsafe.Pointer(pub))

	priv := C.CBytes(make([]byte, SecretKeyLen))
	defer C.free(unsafe.Pointer(priv))

	// pk := C.CString("privateKey")
	// defer C.free(unsafe.Pointer(pk))

	// sk := C.CString("privateKey")
	// defer C.free(unsafe.Pointer(sk))

	_ = C.sqisigngo_gen_keypair(pub, priv)

	fmt.Printf("%x\n\n", C.GoBytes(pub, PublicKeyLen))
	fmt.Printf("%x", C.GoBytes(priv, SecretKeyLen))
	// println(C.GoInt(res))
}
