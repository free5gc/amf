package nas_security

import (
	// "encoding/hex"
	"encoding/hex"
	"fmt"
	"free5gc/lib/aes"
	"free5gc/lib/nas/security"
	"free5gc/src/amf/logger"
)

var AES_BLOCK_SIZE int32 = 16

const (
	MaxKeyBits int32 = 256
)

/*
func printSlice(s string, x []byte) {
	fmt.Printf("%s len=%d cap=%d %v\n",
		s, len(x), cap(x), x)
}
*/

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

	return K1, K2
}

func AesCmacCalculateBlock(cmac []byte, key []byte, msg []byte, len int32) {
	x := make([]byte, 16)
	var flag bool

	// Step 1.  (K1,K2) := Generate_Subkey(K);
	K1, K2 := GenerateSubkey(key)

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
	// fmt.Println("bs ", bs)
	m_last := make([]byte, 16)
	// printSlice("msg", msg)
	// fmt.Printf("%s", hex.Dump(msg))
	// printSlice("K1", K1)
	// fmt.Printf("%s", hex.Dump(K1))
	//38 a6 f0 56 c0 00 00 00  33 32 34 62 63 39 38 40
	//38 a6 f0 56 c0 00 00 00  33 32 34 62 63 39 38 40
	if flag {
		bs := (n - 1) * AES_BLOCK_SIZE
		for i := int32(0); i < 16; i++ {
			m_last[i] = msg[bs+i] ^ K1[i]
		}
	} else {
		var i int32
		bs := (n - 1) * AES_BLOCK_SIZE
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
	// fmt.Println("msg ", msg)
	// fmt.Printf(" %s", hex.Dump(msg))
	// fmt.Println("n", n)
	for i := int32(0); i < n-1; i++ {
		bs := i * AES_BLOCK_SIZE

		for j := int32(0); j < 16; j++ {
			y[j] = x[j] ^ msg[bs+j]
		}
		aes.AesEncrypt(rk, nrounds, y, x)

	}

	//bs = (n - 1) * AES_BLOCK_SIZE
	for j := int32(0); j < 16; j++ {
		y[j] = m_last[j] ^ x[j]
	}
	aes.AesEncrypt(rk, nrounds, y, cmac)
	// printSlice("cmac", cmac)
	// fmt.Printf("%s", hex.Dump(cmac))
}

/*Steps:
1. Apply the subkey generation process in Sec. 6.1 to K to produce K1 and K2.
2. If Mlen = 0, let n = 1; else, let n =[Mlen/b].
3. Let M1, M2, ... , Mn-1, Mn * denote the unique sequence of bit strings such that M =
M1 || M2 || ... || Mn-1 || Mn*, where M1, M2,..., Mn-1 are complete blocks.2
4. If Mn* is a complete block, let Mn = K1 ⊕ Mn*
; else, let Mn = K2 ⊕ (Mn*||10j), where j = nb-Mlen-1.

5. Let C0 = 0b
6. For i = 1 to n, let Ci = CIPHK(Ci-1 ⊕ Mi).
7. Let T = MSBTlen(Cn).
8. Return T
*/

func AesCmacCalculateBit(cmac []byte, key []byte, msg []byte, length int32) {
	plainText := make([]byte, 16)
	var flag bool

	// Step 1.  (K1,K2) := Generate_Subkey(K);
	// Apply the subkey generation process in Sec. 6.1 to K to produce K1 and K2.
	K1, K2 := GenerateSubkey(key)
	// fmt.Printf("k1 %s", hex.Dump(K1))
	// fmt.Printf("k2 %s", hex.Dump(K2))
	// fmt.Printf("msg %s", hex.Dump(msg))
	var n int32
	n = (length + 127) / (AES_BLOCK_SIZE * 8)

	//  Step 2. If Mlen = 0, let n = 1; else, let n =[Mlen/b].
	fmt.Println("length", length)

	if length == 0 {
		n = 1
		flag = false
	} else {
		if (length)%(AES_BLOCK_SIZE*8) == 0 {
			flag = true
		} else {
			flag = false
		}
	}

	/*3. Let M1, M2, ... , Mn-1, Mn * denote the unique sequence of bit strings such that M =
	M1 || M2 || ... || Mn-1 || Mn*, where M1, M2,..., Mn-1 are complete blocks.*/
	/*4. If Mn* is a complete block, let Mn = K1 ⊕ Mn*
	  ; else, let Mn = K2 ⊕ (Mn*||10j), where j = nb-Mlen-1.*/

	// fmt.Println("n", n)
	blockSize := (n - 1) * AES_BLOCK_SIZE
	// fmt.Println("blockSize", blockSize)
	// printSlice("msg", msg)
	// fmt.Printf("%s", hex.Dump(msg))
	// fmt.Println("n", n)
	var i int32
	var j uint32
	mLast := make([]byte, 16)

	if flag {
		// printSlice("K1", K1)
		// fmt.Printf("%s", hex.Dump(K1))
		// printSlice("mLast", mLast)
		// fmt.Printf("%s", hex.Dump(mLast))
		for i = 0; i < 16; i++ {
			mLast[i] = msg[blockSize+i] ^ K1[i]
		}
		// printSlice("after length%(AES_BLOCK_SIZE*8)  mLast", mLast)
		// fmt.Printf(" length(AES_BLOCK_SIZE*8) %s", hex.Dump(mLast))
	} else {
		j = (uint32)(n*128 - length - 1)
		msgLen := len(msg)

		if j < 8 {
			msg[msgLen-1] = msg[msgLen-1] | 1<<j
		} else {
			// printSlice("before msg", msg)
			// fmt.Printf("%s", hex.Dump(msg))
			// fmt.Println("j", j)
			shiftSize := int(j / 8)
			// fmt.Println("shiftSize", shiftSize)
			var concatSlice []byte
			if shiftSize%8 == 0 {
				concatSlice = make([]byte, shiftSize)
			} else {
				concatSlice = make([]byte, shiftSize+1)
			}
			msg = append(msg, concatSlice...)
			// fmt.Println("after append len(msg)", len(msg))
			msg[len(msg)-shiftSize-1] = msg[len(msg)-shiftSize-1] | 1<<(j%8)
			// printSlice("after msg", msg)
			// fmt.Printf("%s", hex.Dump(msg))
		}
		// printSlice("K2", K2)
		// fmt.Printf("%s", hex.Dump(K2))
		for i = 0; i < 16; i++ {
			mLast[i] = (msg[blockSize+i]) ^ K2[i]
		}

		// printSlice("after mLast", mLast)
		// fmt.Printf("%s", hex.Dump(mLast))
	}

	cipherText := make([]byte, 16)
	rk := make([]uint32, rtLength(128))
	var k int32
	var nrounds = aes.AesSetupEnc(rk, key, 128)
	for i = 0; i < n-1; i++ {
		blockSize = i * AES_BLOCK_SIZE
		for k = 0; k < 16; k++ {
			plainText[k] = cipherText[k] ^ msg[blockSize+k]
		}
		aes.AesEncrypt(rk, nrounds, plainText, cipherText)
		// printSlice("after 1111plainText", plainText)
		// fmt.Printf("%s", hex.Dump(plainText))
		// printSlice("after 22222cipherText", cipherText)
		// fmt.Printf("%s", hex.Dump(cipherText))

	}

	for k = 0; k < 16; k++ {
		plainText[k] = cipherText[k] ^ mLast[k]
	}
	aes.AesEncrypt(rk, nrounds, plainText, cipherText)
	// printSlice("after last plainText", plainText)
	// fmt.Printf("%s", hex.Dump(plainText))
	// printSlice("after last cipherText", cipherText)
	// fmt.Printf("%s", hex.Dump(cipherText))

	copy(cmac, cipherText[:4])
}

func NasMacCalculateByAesCmac(AlgoID uint8, KnasInt []byte, Count []byte, Bearer uint8,
	Direction uint8, msg []byte, length int32) ([]byte, error) {
	if len(KnasInt) != 16 {
		return nil, fmt.Errorf("Size of KnasEnc[%d] != 16 bytes)", len(KnasInt))
	}
	if Bearer > 0x1f {
		return nil, fmt.Errorf("Bearer is beyond 5 bits")
	}
	if Direction > 1 {
		return nil, fmt.Errorf("Direction is beyond 1 bits")
	}
	if msg == nil {
		return nil, fmt.Errorf("Nas Payload is nil")
	}

	switch AlgoID {
	case security.AlgIntegrity128NIA0:
		logger.NgapLog.Errorf("NEA1 not implement yet.")
		return nil, nil
	case security.AlgIntegrity128NIA2:
		// Couter[0..32] | BEARER[0..4] | DIRECTION[0] | 0^26
		m := make([]byte, len(msg)+8)

		//First 32 bits are count
		copy(m, Count)
		//Put Bearer and direction together
		m[4] = (Bearer << 3) | (Direction << 2)
		copy(m[8:], msg)
		// var lastBitLen int32

		// lenM := (int32(len(m))) * 8 /* -  lastBitLen*/
		lenM := length
		// fmt.Printf("lenM %d\n", lastBitLen)
		// fmt.Printf("lenM %d\n", lenM)

		logger.NasLog.Debugln("NasMacCalculateByAesCmac", hex.Dump(m))
		logger.NasLog.Debugln("len(m) \n", len(m))

		cmac := make([]byte, 16)

		AesCmacCalculateBit(cmac, KnasInt, m, lenM)
		// only get the most significant 32 bits to be mac value
		return cmac[:4], nil

	case security.AlgIntegrity128NIA3:
		logger.NgapLog.Errorf("NEA3 not implement yet.")
		return nil, nil
	default:
		return nil, fmt.Errorf("Unknown Algorithm Identity[%d]", AlgoID)
	}
}
