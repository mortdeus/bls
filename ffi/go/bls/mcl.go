package bls

/*
#cgo bn256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=4
#cgo bn384 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6
#cgo bn384_256 CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4
#include "config.h"
#include <mcl/bn.h> 
*/
import "C"
import "fmt"
import "unsafe"

// CurveFp254BNb -- 254 bit curve
const CurveFp254BNb = C.mclBn_CurveFp254BNb

// CurveFp382_1 -- 382 bit curve 1
const CurveFp382_1 = C.mclBn_CurveFp382_1

// CurveFp382_2 -- 382 bit curve 2
const CurveFp382_2 = C.mclBn_CurveFp382_2

// BLS12_381
const BLS12_381 = C.MCL_BLS12_381

// IoSerializeHexStr
const IoSerializeHexStr = C.MCLBN_IO_SERIALIZE_HEX_STR

// getfrunitsize() --
func Getfrunitsize() int {
	return int(c.mclbn_fr_unit_size)
}

// getfpunitsize() --
// same as getmaxopunitsize()
func Getfpunitsize() int {
	return int(c.mclbn_fp_unit_size)
}

// getmaxopunitsize --
func Getmaxopunitsize() int {
	return int(c.mclbn_fp_unit_size)
}

// getopunitsize --
// the length of fr is getopunitsize() * 8 bytes
func Getopunitsize() int {
	return int(c.mclbn_getopunitsize())
}

// getcurveorder --
// return the order of g1
func Getcurveorder() string {
	buf := make([]byte, 1024)
	// #nosec
	n := c.mclbn_getcurveorder((*c.char)(unsafe.Pointer(&buf[0])), c.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

// getfieldorder --
// return the characteristic of the field where a curve is defined
func Getfieldorder() string {
	buf := make([]byte, 1024)
	// #nosec
	n := c.mclbn_getfieldorder((*c.char)(unsafe.Pointer(&buf[0])), c.size_t(len(buf)))
	if n == 0 {
		panic("implementation err. size of buf is small")
	}
	return string(buf[:n])
}

// Fr --

type Fr struct{
	v C.mclBnFr
}

//TODO(mortdeus): probably should be trying to use unsafe.Pointer(x.v) here
// cgoPointer --
func (x *Fr) cgoPointer() (p *C.mclBnFr) {
	// #nosec
	return (*C.mclBnFr)(unsafe.Pointer(Fr)) 
}

// Clear --
// BUG(mortedus): memory unsafe 
func (x *Fr) Clear() {
	// #nosec
	C.mclBnFr_clear(x.cgoPointer()) 
}

// SetInt64 --
func (x *Fr) SetInt64(v int64) {
	// #nosec
	C.mclBnFr_setInt(x.cgoPointer(), C.int64_t(v))
}

// getString --                      //BUG(mortdeus) go int -> c int isn't always the same width on different hardware systems
func (x *Fr) SetString(s string, base int) error {
	cs := C.CString(s)
	defer c.free(cs)
	// #nosec
	err := C.mclBnFr_setStr(x.cgoPointer(), cs, C.size_t(len(s)), C.int(base))
	if err != 0 {
		return fmt.Errorf("err mclBnFr_setStr %x", err)
	}
	return nil
}

//BUG(mortdeus): Passing slices around like this is asking for trouble

// Deserialize --
func (x *Fr) Deserialize(buf []byte) error {
	// #nosec
	err := C.mclBnFr_deserialize(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err == 0 {
		return fmt.Errorf("err mclBnFr_deserialize %x", buf)
	}
	return nil
}


// SetLittleEndian --
func (x *Fr) SetLittleEndian(buf []byte) error {
	// #nosec
	err := C.mclBnFr_setLittleEndian(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err mclBnFr_setLittleEndian %x", err)
	}
	return nil
}

// IsEqual --
func (x *Fr) IsEqual(rhs *Fr) bool {
	return C.mclBnFr_isEqual(x.cgoPointer(), rhs.cgoPointer()) == 1
}

// IsZero --
func (x *Fr) IsZero() bool {
	return C.mclBnFr_isZero(x.cgoPointer()) == 1
}

// IsOne --
func (x *Fr) IsOne() bool {
	return C.mclBnFr_isOne(x.cgoPointer()) == 1
}

// SetByCSPRNG --
func (x *Fr) SetByCSPRNG() {
	err := C.mclBnFr_setByCSPRNG(x.cgoPointer())
	if err != 0 {
		panic("err mclBnFr_setByCSPRNG")
	}
}

// SetHashOf --
func (x *Fr) SetHashOf(buf []byte) bool {
	// #nosec
	return C.mclBnFr_setHashOf(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf))) == 0
}

// GetString --
func (x *Fr) GetString(base int) string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnFr_getStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), x.cgoPointer(), C.int(base))
	if n == 0 {
		panic("err mclBnFr_getStr")
	}
	return string(buf[:n])
}

// Serialize --
func (x *Fr) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnFr_serialize(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), x.cgoPointer())
	if n == 0 {
		panic("err mclBnFr_serialize")
	}
	return buf[:n]
}

// FrNeg --
func FrNeg(out *Fr, x *Fr) {
	C.mclBnFr_neg(out.cgoPointer(), x.cgoPointer())
}

// FrInv --
func FrInv(out *Fr, x *Fr) {
	C.mclBnFr_inv(out.cgoPointer(), x.cgoPointer())
}

// FrAdd --
func FrAdd(out *Fr, x *Fr, y *Fr) {
	C.mclBnFr_add(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// FrSub --
func FrSub(out *Fr, x *Fr, y *Fr) {
	C.mclBnFr_sub(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// FrMul --
func FrMul(out *Fr, x *Fr, y *Fr) {
	C.mclBnFr_mul(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// FrDiv --
func FrDiv(out *Fr, x *Fr, y *Fr) {
	C.mclBnFr_div(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// G1 --
type G1 C.mclBnG1

// cgoPointer --
func (x *G1) cgoPointer() (p *C.mclBnG1) {
	// #nosec
	return (*C.mclBnG1)(unsafe.Pointer(x))
}

// Clear --
func (x *G1) Clear() {
	// #nosec
	C.mclBnG1_clear(x.cgoPointer())
}

// GetString --
func (x *G1) SetString(s string, base int) error {
	buf := []byte(s)
	// #nosec
	err := C.mclBnG1_SetStr(x.cgoPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), C.int(base))
	if err != 0 {
		return fmt.Errorf("err mclBnG1_setStr %x", err)
	}
	return nil
}

// Deserialize --
func (x *G1) Deserialize(buf []byte) error {
	// #nosec
	err := C.mclBnG1_deserialize(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err == 0 {
		return fmt.Errorf("err mclBnG1_deserialize %x", buf)
	}
	return nil
}

// IsEqual --
func (x *G1) IsEqual(rhs *G1) bool {
	return C.mclBnG1_isEqual(x.cgoPointer(), rhs.cgoPointer()) == 1
}

// IsZero --
func (x *G1) IsZero() bool {
	return C.mclBnG1_isZero(x.cgoPointer()) == 1
}

// HashAndMapTo --
// TODO(mortdeus)make thread safe
func (x *G1) HashAndMapTo(buf []byte) error {
	// #nosec
	err := C.mclBnG1_hashAndMapTo(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err mclBnG1_hashAndMapTo %x", err)
	}
	return nil
}

// GetString --
func (x *G1) GetString(base int) string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnG1_getStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), x.cgoPointer(), C.int(base))
	if n == 0 {
		panic("err mclBnG1_getStr")
	}
	return string(buf[:n])
}

// Serialize --
func (x *G1) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnG1_serialize(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), x.cgoPointer())
	if n == 0 {
		panic("err mclBnG1_serialize")
	}
	return buf[:n]
}

// G1Neg --
func G1Neg(out *G1, x *G1) {
	C.mclBnG1_neg(out.cgoPointer(), x.cgoPointer())
}

// G1Dbl --
func G1Dbl(out *G1, x *G1) {
	C.mclBnG1_dbl(out.cgoPointer(), x.cgoPointer())
}

// G1Add --
func G1Add(out *G1, x *G1, y *G1) {
	C.mclBnG1_add(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// G1Sub --
func G1Sub(out *G1, x *G1, y *G1) {
	C.mclBnG1_sub(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// G1Mul --
func G1Mul(out *G1, x *G1, y *Fr) {
	C.mclBnG1_mul(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// G1MulCT -- constant time (depending on bit lengh of y)
func G1MulCT(out *G1, x *G1, y *Fr) {
	C.mclBnG1_mulCT(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// G2 --
type G2 C.mclBnG2


// cgoPointer --
func (x *G2) cgoPointer() (p *C.mclBnG2) {
	// #nosec
	return (*C.mclBnG2)(unsafe.Pointer(x))
}

// Clear --
func (x *G2) Clear() {
	// #nosec
	C.mclBnG2_clear(x.cgoPointer())
}

// getString --
func (x *G2) SetString(s string, base int) error {
	buf := []byte(s)
	// #nosec
	err := C.mclBnG2_setStr(x.cgoPointer(), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), C.int(base))
	if err != 0 {
		return fmt.Errorf("err mclBnG2_setStr %x", err)
	}
	return nil
}

// Deserialize --
func (x *G2) Deserialize(buf []byte) error {
	// #nosec
	err := C.mclBnG2_deserialize(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err == 0 {
		return fmt.Errorf("err mclBnG2_deserialize %x", buf)
	}
	return nil
}

// IsEqual --
func (x *G2) IsEqual(rhs *G2) bool {
	return C.mclBnG2_isEqual(x.cgoPointer(), rhs.cgoPointer()) == 1
}

// IsZero --
func (x *G2) IsZero() bool {
	return C.mclBnG2_isZero(x.cgoPointer()) == 1
}

// HashAndMapTo --
func (x *G2) HashAndMapTo(buf []byte) error {
	// #nosec
	err := C.mclBnG2_hashAndMapTo(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != 0 {
		return fmt.Errorf("err mclBnG2_hashAndMapTo %x", err)
	}
	return nil
}

// GetString --
func (x *G2) GetString(base int) string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnG2_getStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), x.cgoPointer(), C.int(base))
	if n == 0 {
		panic("err mclBnG2_getStr")
	}
	return string(buf[:n])
}

// Serialize --
func (x *G2) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnG2_serialize(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), x.cgoPointer())
	if n == 0 {
		panic("err mclBnG2_serialize")
	}
	return buf[:n]
}

// G2Neg --
func G2Neg(out *G2, x *G2) {
	C.mclBnG2_neg(out.cgoPointer(), x.cgoPointer())
}

// G2Dbl --
func G2Dbl(out *G2, x *G2) {
	C.mclBnG2_dbl(out.cgoPointer(), x.cgoPointer())
}

// G2Add --
func G2Add(out *G2, x *G2, y *G2) {
	C.mclBnG2_add(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// G2Sub --
func G2Sub(out *G2, x *G2, y *G2) {
	C.mclBnG2_sub(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// G2Mul --
func G2Mul(out *G2, x *G2, y *Fr) {
	C.mclBnG2_mul(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// GT --
type GT struct {
	v C.mclBnGT
}

// cgoPointer --
func (x *GT) cgoPointer() (p *C.mclBnGT) {
	// #nosec
	return (*C.mclBnGT)(unsafe.Pointer(x))
}

// Clear --
func (x *GT) Clear() {
	// #nosec
	C.mclBnGT_clear(x.cgoPointer())
}

// SetInt64 --
func (x *GT) SetInt64(v int64) {
	// #nosec
	C.mclBnGT_setInt(x.cgoPointer(), C.int64_t(v))
}

// SetString --
func (x *GT) SetString(s string, base int) error {
	cs := C.CString(s)
	// #nosec
	err := C.mclBnGT_setStr(x.cgoPointer(), (*C.char)(unsafe.Pointer(&cs)), C.size_t(len(cs)), C.int(base))
	if err != 0 {
		return fmt.Errorf("err mclBnGT_setStr %x", err)
	}
	return nil
}

// Deserialize --
func (x *GT) Deserialize(buf []byte) error {
	// #nosec
	err := C.mclBnGT_deserialize(x.cgoPointer(), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err == 0 {
		return fmt.Errorf("err mclBnGT_deserialize %x", buf)
	}
	return nil
}

// IsEqual --
func (x *GT) IsEqual(rhs *GT) bool {
	return C.mclBnGT_isEqual(x.cgoPointer(), rhs.cgoPointer()) == 1
}

// IsZero --
func (x *GT) IsZero() bool {
	return C.mclBnGT_isZero(x.cgoPointer()) == 1
}

// IsOne --
func (x *GT) IsOne() bool {
	return C.mclBnGT_isOne(x.cgoPointer()) == 1
}

// getString --
func (x *GT) GetString(base int) string {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnGT_getStr((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), x.cgoPointer(), C.int(base))
	if n == 0 {
		panic("err mclBnGT_getStr")
	}
	return string(buf[:n])
}

// Serialize --
func (x *GT) Serialize() []byte {
	buf := make([]byte, 2048)
	// #nosec
	n := C.mclBnGT_serialize(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), x.cgoPointer())
	if n == 0 {
		panic("err mclBnGT_serialize")
	}
	return buf[:n]
}

// GTNeg --
func GTNeg(out *GT, x *GT) {
	C.mclBnGT_neg(out.cgoPointer(), x.cgoPointer())
}

// GTInv --
func GTInv(out *GT, x *GT) {
	C.mclBnGT_inv(out.cgoPointer(), x.cgoPointer())
}

// GTAdd --
func GTAdd(out *GT, x *GT, y *GT) {
	C.mclBnGT_add(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// GTSub --
func GTSub(out *GT, x *GT, y *GT) {
	C.mclBnGT_sub(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// GTMul --
func GTMul(out *GT, x *GT, y *GT) {
	C.mclBnGT_mul(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// GTDiv --
func GTDiv(out *GT, x *GT, y *GT) {
	C.mclBnGT_div(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// GTPow --
func GTPow(out *GT, x *GT, y *Fr) {
	C.mclBnGT_pow(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// Pairing --
func Pairing(out *GT, x *G1, y *G2) {
	C.mclBn_pairing(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// FinalExp --
func FinalExp(out *GT, x *GT) {
	C.mclBn_finalExp(out.cgoPointer(), x.cgoPointer())
}

// MillerLoop --
func MillerLoop(out *GT, x *G1, y *G2) {
	C.mclBn_millerLoop(out.cgoPointer(), x.cgoPointer(), y.cgoPointer())
}

// getUint64NumToPrecompute --
func GetUint64NumToPrecompute() int {
	return int(C.mclBn_getUint64NumToPrecompute())
}

// PrecomputeG2 --
func PrecomputeG2(Qbuf []uint64, Q *G2) {
	// #nosec
	C.mclBn_precomputeG2((*C.uint64_t)(unsafe.Pointer(&Qbuf[0])), Q.cgoPointer())
}

// PrecomputedMillerLoop --
func PrecomputedMillerLoop(out *GT, P *G1, Qbuf []uint64) {
	// #nosec
	C.mclBn_precomputedMillerLoop(out.cgoPointer(), P.cgoPointer(), (*C.uint64_t)(unsafe.Pointer(&Qbuf[0])))
}

// PrecomputedMillerLoop2 --
func PrecomputedMillerLoop2(out *GT, P1 *G1, Q1buf []uint64, P2 *G1, Q2buf []uint64) {
	// #nosec
	C.mclBn_precomputedMillerLoop2(out.cgoPointer(), P1.cgoPointer(), (*C.uint64_t)(unsafe.Pointer(&Q1buf[0])), P1.cgoPointer(), (*C.uint64_t)(unsafe.Pointer(&Q1buf[0])))
}

// FrEvaluatePolynomial -- y = c[0] + c[1] * x + c[2] * x^2 + ...
func FrEvaluatePolynomial(y *Fr, c []Fr, x *Fr) error {
	// #nosec
	err := C.mclBn_FrEvaluatePolynomial(y.cgoPointer(), (*C.mclBnFr)(unsafe.Pointer(&c[0])), (C.size_t)(len(c)), x.cgoPointer())
	if err != 0 {
		return fmt.Errorf("err mclBn_FrEvaluatePolynomial")
	}
	return nil
}

// G1EvaluatePolynomial -- y = c[0] + c[1] * x + c[2] * x^2 + ...
func G1EvaluatePolynomial(y *G1, c []G1, x *Fr) error {
	// #nosec
	err := C.mclBn_G1EvaluatePolynomial(y.cgoPointer(), (*C.mclBnG1)(unsafe.Pointer(&c[0])), (C.size_t)(len(c)), x.cgoPointer())
	if err != 0 {
		return fmt.Errorf("err mclBn_G1EvaluatePolynomial")
	}
	return nil
}

// G2EvaluatePolynomial -- y = c[0] + c[1] * x + c[2] * x^2 + ...
func G2EvaluatePolynomial(y *G2, c []G2, x *Fr) error {
	// #nosec
	err := C.mclBn_G2EvaluatePolynomial(y.cgoPointer(), (*C.mclBnG2)(unsafe.Pointer(&c[0])), (C.size_t)(len(c)), x.cgoPointer())
	if err != 0 {
		return fmt.Errorf("err mclBn_G2EvaluatePolynomial")
	}
	return nil
}

// FrLagrangeInterpolation --
func FrLagrangeInterpolation(out *Fr, xVec []Fr, yVec []Fr) error {
	if len(xVec) != len(yVec) {
		return fmt.Errorf("err FrLagrangeInterpolation:bad size")
	}
	// #nosec
	err := C.mclBn_FrLagrangeInterpolation(out.cgoPointer(), (*C.mclBnFr)(unsafe.Pointer(&xVec[0])), (*C.mclBnFr)(unsafe.Pointer(&yVec[0])), (C.size_t)(len(xVec)))
	if err != 0 {
		return fmt.Errorf("err FrLagrangeInterpolation")
	}
	return nil
}

// G1LagrangeInterpolation --
func G1LagrangeInterpolation(out *G1, xVec []Fr, yVec []G1) error {
	if len(xVec) != len(yVec) {
		return fmt.Errorf("err G1LagrangeInterpolation:bad size")
	}
	// #nosec
	err := C.mclBn_G1LagrangeInterpolation(out.cgoPointer(), (*C.mclBnFr)(unsafe.Pointer(&xVec[0])), (*C.mclBnG1)(unsafe.Pointer(&yVec[0])), (C.size_t)(len(xVec)))
	if err != 0 {
		return fmt.Errorf("err G1LagrangeInterpolation")
	}
	return nil
}

// G2LagrangeInterpolation --
func G2LagrangeInterpolation(out *G2, xVec []Fr, yVec []G2) error {
	if len(xVec) != len(yVec) {
		return fmt.Errorf("err G2LagrangeInterpolation:bad size")
	}
	// #nosec
	err := C.mclBn_G2LagrangeInterpolation(out.cgoPointer(), (*C.mclBnFr)(unsafe.Pointer(&xVec[0])), (*C.mclBnG2)(unsafe.Pointer(&yVec[0])), (C.size_t)(len(xVec)))
	if err != 0 {
		return fmt.Errorf("err G2LagrangeInterpolation")
	}
	return nil
}
