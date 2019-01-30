// +build swapg

package bls

/*
#cgo bn256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=4 -DMCLBN_COMPILED_TIME_VAR=144 
#cgo bn256 LDFLAGS:-lbls256 
#cgo bn384 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_COMPILED_TIME_VAR=166  
#cgo bn384 LDFLAGS:-lbls384
#cgo bn384_256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 -DMCLBN_COMPILED_TIME_VAR=146  
#cgo bn384_256 LDFLAGS:-lbls384_256
#cgo LDFLAGS:-lbls384
#cgo LDFLAGS:-lcrypto -lgmp -lgmpxx -lstdc++
#include "config.h"
#include <bls/bls.h>
*/
import "C"

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
type PublicKey struct{
	v G1 
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
type Sign struct{
	v G2
}
/*
#ifdef BLS_SWAP_G
// get a generator of G1
BLS_DLL_API void blsGetGeneratorOfG1(blsPublicKey *pub);
#else
*/
func GetGeneratorOfG(pkey *PublicKey){
	C.blsGetGeneratorOfG1(pkey.v.cgoPointer())
}
/*
// get a generator of G2
BLS_DLL_API void blsGetGeneratorOfG2(blsPublicKey *pub);
#endif
*/

/* bls.hpp
#ifdef BLS_SWAP_G
			const int elemNum = 2;
#else
			const int elemNum = 4;
#endif
*/
const ElemNum = 2;
/*
#ifdef BLS_SWAP_G
		size_t n = mclBnG1_getStr(&str[0], str.size(), &self_.v, ioMode);
#else
		size_t n = mclBnG2_getStr(&str[0], str.size(), &self_.v, ioMode);
#endif
*/
func (bn *Bn) GetString(ioMode int) (string, int){
		cs := C.CString(string(make([]byte, 1028)))
		defer C.free(unsafe.Pointer(s))
		n := C.mclBnG1_getStr(cs, len(cs), &bn.G, ioMode)
		return string(cs), n


}
/*

#ifdef BLS_SWAP_G
		int ret = mclBnG1_setStr(&self_.v, str.c_str(), str.size(), ioMode);
#else
		int ret = mclBnG2_setStr(&self_.v, str.c_str(), str.size(), ioMode);
#endif
*/

func (bn *Bn) SetString(s string, ioMode int) int{
		cs := C.CString(s)
		defer C.free(unsafe.Pointer(s))
		C.mclBnG1_setStr(cs, len(s), &bn.G, ioMode)


}