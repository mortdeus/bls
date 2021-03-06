// +build !swap

package bls

/*
#cgo bn256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=4
#cgo bn256 LDFLAGS:-lbls256
#cgo bn384 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo bn384 LDFLAGS:-lbls384
#cgo bn384_256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4
#cgo bn384_256 LDFLAGS:-lbls384_256
#cgo LDFLAGS:-lbls384
#cgo LDFLAGS:-lcrypto -lgmp -lgmpxx -lstdc++
#cgo CFLAGS:-DBLS_SWAP_G=0
#include "config.h"
#include <bls/bls.h>
*/
import "C"
//import "fmt"
import "unsafe"

/*bls.h
#ifdef BLS_SWAP_G

	//	error if BLS_SWAP_G is inconsistently used between library and exe

	#undef MCLBN_COMPILED_TIME_VAR
	#define )
#endif
*/

/*
typedef struct {
#ifdef BLS_SWAP_G
	mclBnG1 v;
#else
	mclBnG2 v;
#endif
} blsPublicKey;
*/
type PublicKey struct {
	v G2
}

// getPointer --
func (pub *PublicKey) getPointer() (p *C.blsPublicKey) {
	// #nosec
	return (*C.blsPublicKey)(unsafe.Pointer(pub))
}

// Serialize --
func (pub *PublicKey) Serialize() []byte {
	return pub.v.Serialize()
}

// Deserialize --
func (pub *PublicKey) Deserialize(buf []byte) error {
	return pub.v.Deserialize(buf)
}

// SerializeToHexStr --
func (pub *PublicKey) SerializeToHexStr() string {
	return pub.v.GetString(IoSerializeHexStr)
}

// DeserializeHexStr --
func (pub *PublicKey) DeserializeHexStr(s string) error {
	return pub.v.SetString(s, IoSerializeHexStr)
}

// GetHexString --
func (pub *PublicKey) GetHexString() string {
	return pub.v.GetString(16)
}

// SetHexString --
func (pub *PublicKey) SetHexString(s string) error {
	return pub.v.SetString(s, 16)
}

// IsEqual --
func (pub *PublicKey) IsEqual(rhs *PublicKey) bool {
	return pub.v.IsEqual(&rhs.v)
}

// Add --
func (pub *PublicKey) Add(rhs *PublicKey) {
	G2Add(&pub.v, &pub.v, &rhs.v)
}

// Set --
func (pub *PublicKey) Set(mpk []PublicKey, id *ID) error {
	// #nosec
	return G2EvaluatePolynomial(&pub.v, *(*[]G2)(unsafe.Pointer(&mpk)), &id.v)
}

// Recover --
func (pub *PublicKey) Recover(pubVec []PublicKey, idVec []ID) error {
	// #nosec
	return G2LagrangeInterpolation(&pub.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]G2)(unsafe.Pointer(&pubVec)))
}

/*
typedef struct {
#ifdef BLS_SWAP_G
	mclBnG2 v;
#else
	mclBnG1 v;
#endif
} blsSignature;
*/
type Sign struct {
	v G1
}

// Sign  --

// getPointer --
func (sign *Sign) getPointer() (p *C.blsSignature) {
	// #nosec
	return (*C.blsSignature)(unsafe.Pointer(sign))
}

// Serialize --
func (sign *Sign) Serialize() []byte {
	return sign.v.Serialize()
}

// Deserialize --
func (sign *Sign) Deserialize(buf []byte) error {
	return sign.v.Deserialize(buf)
}

// SerializeToHexStr --
func (sign *Sign) SerializeToHexStr() string {
	return sign.v.GetString(IoSerializeHexStr)
}

// DeserializeHexStr --
func (sign *Sign) DeserializeHexStr(s string) error {
	return sign.v.SetString(s, IoSerializeHexStr)
}

// GetHexString --
func (sign *Sign) GetHexString() string {
	return sign.v.GetString(16)
}

// SetHexString --
func (sign *Sign) SetHexString(s string) error {
	return sign.v.SetString(s, 16)
}

// IsEqual --
func (sign *Sign) IsEqual(rhs *Sign) bool {
	return sign.v.IsEqual(&rhs.v)
}

// Add --
func (sign *Sign) Add(rhs *Sign) {
	C.blsSignatureAdd(sign.getPointer(), rhs.getPointer())
}

// Recover --
func (sign *Sign) Recover(signVec []Sign, idVec []ID) error {
	// #nosec
	return G1LagrangeInterpolation(&sign.v, *(*[]Fr)(unsafe.Pointer(&idVec)), *(*[]G1)(unsafe.Pointer(&signVec)))
}

// Verify --
func (sign *Sign) Verify(pub *PublicKey, m string) bool {
	buf := []byte(m)
	// #nosec
	return C.blsVerify(sign.getPointer(), pub.getPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf))) == 1
}

// VerifyPop --
func (sign *Sign) VerifyPop(pub *PublicKey) bool {
	return C.blsVerifyPop(sign.getPointer(), pub.getPointer()) == 1
}

// VerifyHash --
func (sign *Sign) VerifyHash(pub *PublicKey, hash []byte) bool {
	// #nosec
	return C.blsVerifyHash(sign.getPointer(), pub.getPointer(), unsafe.Pointer(&hash[0]), C.size_t(len(hash))) == 1
}

// VerifyAggregateHashes --
func (sign *Sign) VerifyAggregateHashes(pubVec []PublicKey, hash [][]byte) bool {
	hashByte := GetOpUnitSize() * 8
	n := len(hash)
	h := make([]byte, n*hashByte)
	for i := 0; i < n; i++ {
		hn := len(hash[i])
		copy(h[i*hashByte:(i+1)*hashByte], hash[i][0:Min(hn, hashByte)])
	}
	return C.blsVerifyAggregatedHashes(sign.getPointer(), pubVec[0].getPointer(), unsafe.Pointer(&h[0]), C.size_t(hashByte), C.size_t(n)) == 1
}

/*
#ifdef BLS_SWAP_G
	// get a generator of G1
	BLS_DLL_API void blsGetGeneratorOfG1(blsPublicKey *pub);
#else
	// get a generator of G2
	BLS_DLL_API void blsGetGeneratorOfG2(blsPublicKey *pub);
#endif
*/

*/
func GetGeneratorOfG(pkey *PublicKey) {
	panic("unimplemented")
	//C.blsGetGeneratorOfG1(pkey.v.cgoPointer())
}


/* bls.hpp
#ifdef BLS_SWAP_G
			const int elemNum = 2;
#else
			const int elemNum = 4;
#endif
*/
const ElemNum = 4

/*
#ifdef BLS_SWAP_G
		size_t n = mclBnG1_getStr(&str[0], str.size(), &self_.v, ioMode);
#else
		size_t n = mclBnG2_getStr(&str[0], str.size(), &self_.v, ioMode);
#endif
*/
// func (g *G2) GetString(ioMode int) string {
// 	cs := C.CString(string(make([]byte, 1028)))
// 	defer C.free(unsafe.Pointer(cs))
// 	n := C.mclBnG2_getStr(cs, 1028, g.cgoPointer(), C.int(ioMode))

// 	if n == 0 {
// 		panic("err mclBnG2_getStr")
// 	}
// 	return C.GoString(cs)

// }

/*

#ifdef BLS_SWAP_G
		int ret = mclBnG1_setStr(&self_.v, str.c_str(), str.size(), ioMode);
#else
		int ret = mclBnG2_setStr(&self_.v, str.c_str(), str.size(), ioMode);
#endif
*/

// func (g *G2) SetString(s string, ioMode int) error {
// 	cs := C.CString(s)
// 	defer C.free(unsafe.Pointer(s))
// 	err := C.mclBnG2_setStr(g.cgoPointer(), cs, C.size_t(len(s)), C.int(ioMode))
// 	if err != 0 {
// 		return fmt.Errorf("err mclBnG2_setStr %x", err)
// 	}
// 	return nil

// }
