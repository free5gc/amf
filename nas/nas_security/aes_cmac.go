package nas_security

import (
	// "encoding/hex"
	"fmt"
	"free5gc/lib/aes"
)

var AES_BLOCK_SIZE int32 = 16

const (
	MaxKeyBits int32 = 256
)

func printSlice(s string, x []byte) {
	fmt.Printf("%s len=%d cap=%d %v\n",
		s, len(x), cap(x), x)
}

func rtLength(keybits int) int {
	return (keybits)/8 + 28
}

func GenerateSubkey(key []byte) (K1 []byte, K2 []byte) {
	zero := make([]byte, 16)
	rb := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87}
	K1 = make([]byte, 16)
	K2 = make([]byte, 16)
	// printSlice("zeroArr", zero)
	// printSlice("rbArr", rb)

	L := make([]byte, 16)
	rk := make([]uint32, rtLength(128))
	const keyBits int = 128

	/* Step 1.  L := AES-128(K, const_Zero) */
	var nrounds = aes.AesSetupEnc(rk, key, keyBits)
	// fmt.Printf("nrounds: %d\n", nrounds)
	// printSlice("key", key)
	// fmt.Printf("%s", hex.Dump(key))

	aes.AesEncrypt(rk, nrounds, zero, L)
	// printSlice("zeroArr", zero)
	// printSlice("L", L)
	// fmt.Printf("%s", hex.Dump(L))

	/* Step 2.  if MSB(L) is equal to 0 */
	if (L[0] & 0x80) == 0 {
		for i := 0; i < 15; i++ {
			/* then    k1 := L << 1; */
			var b byte
			if (L[i+1] & 0x80) != 0 {
				b = 1
			} else {
				b = 0
			}
			K1[i] = ((L[i] << 1) & 0xfe) | b
		}
		K1[15] = ((L[15] << 1) & 0xfe)

	} else {
		/* else    K1 := (L << 1) XOR const_Rb; */
		for i := 0; i < 15; i++ {
			var b byte
			if (L[i+1] & 0x80) != 0 {
				b = 1
			} else {
				b = 0
			}
			K1[i] = (((L[i] << 1) & 0xfe) | b) ^ rb[i]
		}
		K1[15] = ((L[15] << 1) & 0xfe) ^ rb[15]
	}
	// printSlice("K1", K1)
	// fmt.Printf("%s", hex.Dump(K1))

	/* Step 3.  if MSB(k1) is equal to 0 */
	if K1[0]&0x80 == 0 {
		for i := 0; i < 15; i++ {
			/* then    k1 := L << 1; */
			var b byte
			if (K1[i+1] & 0x80) != 0 {
				b = 1
			} else {
				b = 0
			}
			K2[i] = ((K1[i] << 1) & 0xfe) | b
		}
		K2[15] = ((K1[15] << 1) & 0xfe)

	} else {
		/* else    k2 := (k2 << 1) XOR const_Rb; */
		for i := 0; i < 15; i++ {
			/* then    k1 := L << 1; */
			var b byte
			if (K1[i+1] & 0x80) != 0 {
				b = 1
			} else {
				b = 0
			}
			K2[i] = (((K1[i] << 1) & 0xfe) | b) ^ rb[i]
		}

		K2[15] = ((K1[15] << 1) & 0xfe) ^ rb[15]
	}
	// printSlice("K2", K2)
	// fmt.Printf("%s", hex.Dump(K2))

	return
}

func AesCmacCalculateBlock(cmac []byte, key []byte, msg []byte, len int32) {
	x := make([]byte, 16)
	var flag bool
	K1 := make([]byte, 16)
	K2 := make([]byte, 16)
	// Step 1.  (K1,K2) := Generate_Subkey(K);
	K1, K2 = GenerateSubkey(key)

	//  Step 2.  n := ceil(len/const_Bsize);
	n := (len + 15) / AES_BLOCK_SIZE

	/* Step 3.  if n = 0
	   then
	       n := 1;
	       flag := false;
	   else
	       if len mod const_Bsize is 0
	       then flag := true;
	       else flag := false;
	*/
	if n == 0 {
		n = 1
		flag = false
	} else {
		if len%AES_BLOCK_SIZE == 0 {
			flag = true
		} else {
			flag = false
		}
	}

	/* Step 4.  if flag is true
	   then M_last := M_n XOR K1;
	   else M_last := padding(M_n) XOR K2;
	*/
	bs := (n - 1) * AES_BLOCK_SIZE
	// fmt.Println("bs ", bs)
	var i int32 = 0
	m_last := make([]byte, 16)
	// printSlice("msg", msg)
	// fmt.Printf("%s", hex.Dump(msg))
	// printSlice("K1", K1)
	// fmt.Printf("%s", hex.Dump(K1))
	//38 a6 f0 56 c0 00 00 00  33 32 34 62 63 39 38 40
	//38 a6 f0 56 c0 00 00 00  33 32 34 62 63 39 38 40
	if flag {
		for i = 0; i < 16; i++ {
			m_last[i] = msg[bs+i] ^ K1[i]
		}
	} else {
		for i = 0; i < len%AES_BLOCK_SIZE; i++ {
			m_last[i] = msg[bs+i] ^ K2[i]
		}

		m_last[i] = 0x80 ^ K2[i]

		for i = i + 1; i < AES_BLOCK_SIZE; i++ {
			m_last[i] = 0x00 ^ K2[i]
		}
	}

	/* Step 5.  X := const_Zero;  */
	/* Step 6.  for i := 1 to n-1 do
	       begin
	           Y := X XOR M_i;
	           X := AES-128(K,Y);
	       end
	   Y := M_last XOR X;
	   T := AES-128(K,Y);
	*/
	// printSlice("x", x)
	// fmt.Printf(" %s", hex.Dump(x))

	rk := make([]uint32, rtLength(128))
	var nrounds = aes.AesSetupEnc(rk, key, 128)
	// fmt.Printf("nrounds: %d\n", nrounds)
	y := make([]byte, 16)
	var j int32 = 0
	// fmt.Println("msg ", msg)
	// fmt.Printf(" %s", hex.Dump(msg))
	// fmt.Println("n", n)
	for i = 0; i < n-1; i++ {
		bs = i * AES_BLOCK_SIZE

		for j = 0; j < 16; j++ {
			y[j] = x[j] ^ msg[bs+j]
		}
		aes.AesEncrypt(rk, nrounds, y, x)

	}

	bs = (n - 1) * AES_BLOCK_SIZE
	for j = 0; j < 16; j++ {
		y[j] = m_last[j] ^ x[j]
	}
	aes.AesEncrypt(rk, nrounds, y, cmac)
	// printSlice("cmac", cmac)
	// fmt.Printf("%s", hex.Dump(cmac))
}
