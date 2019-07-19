package other

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"os"
)

func EncryptBlock(key []byte, dst, src []byte) {
	subkeys := generateSubKeys(key)
	cryptBlock(subkeys, make([]uint32, 4), make([]byte, 16), dst, src, false)
}

func DecryptBlock(key []byte, dst, src []byte) {
	subkeys := generateSubKeys(key)
	cryptBlock(subkeys, make([]uint32, 4), make([]byte, 16), dst, src, true)
}

func ReadKeyFromMem(data []byte, pwd []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if x509.IsEncryptedPEMBlock(block) {
		if block.Type != "SM4 ENCRYPTED KEY" {
			return nil, errors.New("SM4: unknown type")
		}
		if pwd == nil {
			return nil, errors.New("SM4: need passwd")
		}
		data, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if block.Type != "SM4 KEY" {
		return nil, errors.New("SM4: unknown type")
	}
	return block.Bytes, nil
}


func WriteKeytoMem(key []byte, pwd []byte) ([]byte, error) {
	if pwd != nil {
		block, err := x509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	} else {
		block := &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
		return pem.EncodeToMemory(block), nil
	}
}

func WriteKeyToPem(FileName string, key []byte, pwd []byte) (bool, error) {
	var block *pem.Block

	if pwd != nil {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, x509.PEMCipherAES256)
		if err != nil {
			return false, err
		}
	} else {
		block = &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, nil
	}
	return true, nil
}