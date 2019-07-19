package other

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"github.com/chinaso/golangGM/util"
	"testing"
)

type sm4CbcTestData struct {
	key []byte
	iv  []byte
	in  []byte
	out []byte
}

var testData = []sm4CbcTestData{
	{
		key: []byte{0x7b, 0xea, 0x0a, 0xa5, 0x45, 0x8e, 0xd1, 0xa3, 0x7d, 0xb1, 0x65, 0x2e, 0xfb, 0xc5, 0x95, 0x05},
		iv:  []byte{0x70, 0xb6, 0xe0, 0x8d, 0x46, 0xee, 0x82, 0x24, 0x45, 0x60, 0x0b, 0x25, 0xc4, 0x71, 0xfa, 0xba},
		in:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		out: []byte{0xca, 0x55, 0xc5, 0x15, 0x0b, 0xf7, 0xf4, 0x6f, 0xc9, 0x89, 0x2a, 0xce, 0x49, 0x78, 0x93, 0x03},
	},
	{
		key: []byte{0x7b, 0xea, 0x0a, 0xa5, 0x45, 0x8e, 0xd1, 0xa3, 0x7d, 0xb1, 0x65, 0x2e, 0xfb, 0xc5, 0x95, 0x05},
		iv:  []byte{0x70, 0xb6, 0xe0, 0x8d, 0x46, 0xee, 0x82, 0x24, 0x45, 0x60, 0x0b, 0x25, 0xc4, 0x71, 0xfa, 0xba},
		in:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		out: []byte{0x95, 0xe1, 0xec, 0x3b, 0x56, 0x4a, 0x46, 0x71, 0xe7, 0xd6, 0xb1, 0x10, 0xe9, 0x09, 0x0b, 0x1b, 0xb7, 0xb5, 0x9e, 0x8d, 0x74, 0x47, 0x1e, 0x70, 0x86, 0x04, 0x6b, 0xe8, 0x78, 0x00, 0x45, 0x32},
	},
}

func TestSm4Cipher_Encrypt(t *testing.T) {
	for _, data := range testData {
		c, err := NewCipher(data.key)
		if err != nil {
			t.Error(err.Error())
			return
		}

		encrypter := cipher.NewCBCEncrypter(c, data.iv)
		result := make([]byte, len(data.out))
		encrypter.CryptBlocks(result, util.PKCS5Padding(data.in, BlockSize))
		fmt.Printf("encrypt result:%s\n", hex.EncodeToString(result))
		if !bytes.Equal(result, data.out) {
			t.Error("encrypt result not equal expected")
			return
		}

		decrypter := cipher.NewCBCDecrypter(c, data.iv)
		plain := make([]byte, len(result))
		decrypter.CryptBlocks(plain, result)
		fmt.Printf("decrypt result:%s\n", hex.EncodeToString(plain))
		plain = util.PKCS5UnPadding(plain)
		if !bytes.Equal(plain, data.in) {
			t.Error("decrypt result not equal expected")
			return
		}
	}
}
