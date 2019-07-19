package sm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/chinaso/golangGM/sm3"

	//"crypto/sha1"
	////"crypto/sha256"
	//"crypto/sha512"
	"crypto/sm2"
	"encoding/pem"
	"io/ioutil"
	"os"

	//"crypto/sm2"

	"encoding/asn1"
	"errors"
	"github.com/chinaso/golangGM/x509/pkix"
	"hash"

	"math/big"
	"reflect"
)

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}


var (

	oidPBES1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}  // pbeWithMD5AndDES-CBC(PBES1)
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13} // id-PBES2(PBES2)
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12} // id-PBKDF2

	oidKEYMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidKEYSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidKEYSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidKEYSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	oidSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

func ParsePKCS8UnecryptedSM2PrivateKey(der []byte) (*PrivateKey, error) {
	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(privKey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	return ParseSM2PrivateKey(privKey.PrivateKey)
}

func ParsePKCS8PrivateKey(der, pwd []byte) (*PrivateKey, error) {
	if pwd == nil {
		return ParsePKCS8UnecryptedSM2PrivateKey(der)
	}
	return ParsePKCS8EcryptedSM2PrivateKey(der, pwd)
}

func ParsePKCS8EcryptedSM2PrivateKey(der, pwd []byte) (*PrivateKey, error) {
	var keyInfo EncryptedPrivateKeyInfo

	_, err := asn1.Unmarshal(der, &keyInfo)
	if err != nil {
		return nil, errors.New("x509: unknown format")
	}
	if !reflect.DeepEqual(keyInfo.EncryptionAlgorithm.IdPBES2, oidPBES2) {
		return nil, errors.New("x509: only support PBES2")
	}
	encryptionScheme := keyInfo.EncryptionAlgorithm.Pbes2Params.EncryptionScheme
	keyDerivationFunc := keyInfo.EncryptionAlgorithm.Pbes2Params.KeyDerivationFunc
	if !reflect.DeepEqual(keyDerivationFunc.IdPBKDF2, oidPBKDF2) {
		return nil, errors.New("x509: only support PBKDF2")
	}
	pkdf2Params := keyDerivationFunc.Pkdf2Params
	if !reflect.DeepEqual(encryptionScheme.EncryAlgo, oidAES128CBC) &&
		!reflect.DeepEqual(encryptionScheme.EncryAlgo, oidAES256CBC) {
		return nil, errors.New("x509: unknow encryption algorithm")
	}
	iv := encryptionScheme.IV
	salt := pkdf2Params.Salt
	iter := pkdf2Params.IterationCount
	encryptedKey := keyInfo.EncryptedData
	var key []byte
	switch {
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYMD5):
		key = pbkdf(pwd, salt, iter, 32, md5.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA1):
		key = pbkdf(pwd, salt, iter, 32, sha1.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA256):
		key = pbkdf(pwd, salt, iter, 32, sha256.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA512):
		key = pbkdf(pwd, salt, iter, 32, sha512.New)
		break
	default:
		return nil, errors.New("x509: unknown hash algorithm")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedKey, encryptedKey)
	rKey, err := ParsePKCS8UnecryptedSM2PrivateKey(encryptedKey)
	if err != nil {
		return nil, errors.New("pkcs8: incorrect password")
	}
	return rKey, nil
}

type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}
func ParseSM2PublicKey(der []byte) (*PublicKey, error) {
	var pubkey pkixPublicKey

	if _, err := asn1.Unmarshal(der, &pubkey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(pubkey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	curve := P256Sm2()
	x, y := elliptic.Unmarshal(curve, pubkey.BitString.Bytes)
	pub := PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return &pub, nil
}


func ParseSM2PrivateKey(der []byte) (*PrivateKey, error) {
	//var privKey sm2PrivateKey
	var privKey sm2PrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse SM2 private key: " + err.Error())
	}
	curve := sm2.P256Sm2()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(PrivateKey)
	priv.Curve = curve
	priv.D = k
	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
	return priv, nil
}


func MarshalSM2PrivateKey(key *PrivateKey, pwd []byte) ([]byte, error) {
	if pwd == nil {
		return MarshalSM2UnecryptedPrivateKey(key)
	}
	return MarshalSM2EcryptedPrivateKey(key, pwd)
}

func MarshalSM2PublicKey(key *PublicKey) ([]byte, error) {
	var r pkixPublicKey
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	r.Algo = algo
	r.BitString = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	return asn1.Marshal(r)
}

func MarshalSM2UnecryptedPrivateKey(key *PrivateKey) ([]byte, error) {
	var r pkcs8
	var priv sm2PrivateKey
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	priv.Version = 1
	priv.NamedCurveOID = oidNamedCurveP256SM2
	priv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	priv.PrivateKey = key.D.Bytes()
	r.Version = 0
	r.Algo = algo
	r.PrivateKey, _ = asn1.Marshal(priv)
	return asn1.Marshal(r)
}

// ----------------------------------------------------- //
func MarshalSM2EcryptedPrivateKey(PrivKey *PrivateKey, pwd []byte) ([]byte, error) {
	der, err := MarshalSM2UnecryptedPrivateKey(PrivKey)
	if err != nil {
		return nil, err
	}
	iter := 2048
	salt := make([]byte, 8)
	iv := make([]byte, 16)
	rand.Reader.Read(salt)
	rand.Reader.Read(iv)
	//key := pbkdf(pwd, salt, iter, 32, sha1.New) // 默认是SHA1
	key := pbkdf(pwd, salt, iter, 32, sm3.New)
	padding := sm3.BlockSize - len(der)%sm3.BlockSize
	if padding > 0 {
		n := len(der)
		der = append(der, make([]byte, padding)...)
		for i := 0; i < padding; i++ {
			der[n+i] = byte(padding)
		}
	}
	encryptedKey := make([]byte, len(der))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedKey, der)
	var algorithmIdentifier pkix.AlgorithmIdentifier
	algorithmIdentifier.Algorithm = oidKEYSHA1
	algorithmIdentifier.Parameters.Tag = 5
	algorithmIdentifier.Parameters.IsCompound = false
	algorithmIdentifier.Parameters.FullBytes = []byte{5, 0}
	keyDerivationFunc := Pbes2KDfs{
		oidPBKDF2,
		Pkdf2Params{
			salt,
			iter,
			algorithmIdentifier,
		},
	}
	encryptionScheme := Pbes2Encs{
		oidAES256CBC,
		iv,
	}
	pbes2Algorithms := Pbes2Algorithms{
		oidPBES2,
		Pbes2Params{
			keyDerivationFunc,
			encryptionScheme,
		},
	}
	encryptedPkey := EncryptedPrivateKeyInfo{
		pbes2Algorithms,
		encryptedKey,
	}
	return asn1.Marshal(encryptedPkey)
}


// copy from crypto/pbkdf2.go
func pbkdf(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}


// reference to https://www.rfc-editor.org/rfc/rfc5958.txt
type PrivateKeyInfo struct {
	Version             int // v1 or v2
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

// reference to https://www.rfc-editor.org/rfc/rfc5958.txt
type EncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm Pbes2Algorithms
	EncryptedData       []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Algorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	Pbes2Params Pbes2Params
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2Params struct {
	KeyDerivationFunc Pbes2KDfs // PBES2-KDFs
	EncryptionScheme  Pbes2Encs // PBES2-Encs
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pbes2KDfs struct {
	IdPBKDF2    asn1.ObjectIdentifier
	Pkdf2Params Pkdf2Params
}

type Pbes2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

// reference to https://www.ietf.org/rfc/rfc2898.txt
type Pkdf2Params struct {
	Salt           []byte
	IterationCount int
	Prf            pkix.AlgorithmIdentifier
}


// ----------------------------------------- //
func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*PrivateKey, error) {
	var block *pem.Block

	block, _ = pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParsePKCS8PrivateKey(block.Bytes, pwd)
	return priv, err
}

func ReadPrivateKeyFromPem(FileName string, pwd []byte) (*PrivateKey, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKeyFromMem(data, pwd)
}

func WritePrivateKeytoMem(key *PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block

	der, err := MarshalSM2PrivateKey(key, pwd)
	if err != nil {
		return nil, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	return pem.EncodeToMemory(block), nil
}

func WritePrivateKeytoPem(FileName string, key *PrivateKey, pwd []byte) (bool, error) {
	var block *pem.Block

	der, err := MarshalSM2PrivateKey(key, pwd)
	if err != nil {
		return false, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ReadPublicKeyFromMem(data []byte, _ []byte) (*PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	pub, err := ParseSM2PublicKey(block.Bytes)
	return pub, err
}

func ReadPublicKeyFromPem(FileName string, pwd []byte) (*PublicKey, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPublicKeyFromMem(data, pwd)
}

func WritePublicKeytoMem(key *PublicKey, _ []byte) ([]byte, error) {
	der, err := MarshalSM2PublicKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func WritePublicKeytoPem(FileName string, key *PublicKey, _ []byte) (bool, error) {
	der, err := MarshalSM2PublicKey(key)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	defer file.Close()
	if err != nil {
		return false, err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}
