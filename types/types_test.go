package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"os"
	"testing"
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

var token = DecryptTaskToken{
	ExpireTime:    time.Now().Unix() + 100,
	FileId:        [32]byte{1},
	RecryptorSalt: [32]byte{1},
	Secret:        [32]byte{1},
	RemoteAddr:    "127.0.0.1",
	ViewerAccount: [20]byte{1},
	Contract:      "test",
}

func TestPrivateKey(t *testing.T) {
	//testing NewKeyFile
	fname := "key.txt"
	os.RemoveAll(fname)
	keyFile := NewKeyFile(fname)
	require.Equal(t, keyFile.filename, fname)

	//testing whether private key sealed to file and key recovered is the same
	key1 := keyFile.RecoveryPrivateKey(true)
	key2 := keyFile.RecoveryPrivateKey(true)
	require.Equal(t, crypto.FromECDSA(key1), crypto.FromECDSA(key2))

	os.RemoveAll(fname)
	key3 := keyFile.generatePrivateKey(true)
	keyFile.SealKeyToFile(key3, true)
	key4 := keyFile.RecoveryPrivateKey(true)
	require.Equal(t, crypto.FromECDSA(key3), crypto.FromECDSA(key4))
}
func TestToBytes(t *testing.T) {
	//txInfo and ToBytes() testing
	tx := TxInfo{
		ChainId:   big.NewInt(int64(1)),
		Timestamp: big.NewInt(int64(1)),
		TxHash:    common.BigToHash(big.NewInt(int64(1))),
		From:      common.HexToAddress("1"),
		To:        common.HexToAddress("1"),
		Value:     big.NewInt(int64(1)),
		Data:      []byte{1}}

	//testing ToBytes()
	bz := make([]byte, 0)
	for i := 1; i <= 3; i++ {
		bz = append(bz, append(make([]byte, 31), 1)...)
	}
	for i := 1; i <= 2; i++ {
		bz = append(bz, append(make([]byte, 19), 1)...)
	}
	bz = append(append(bz, append(make([]byte, 31), 1)...), 1)
	require.Equal(t, bz, tx.ToBytes())

	//LogInfo and ToBytes() testing
	logInfo := LogInfo{
		ChainId:   big.NewInt(int64(1)),
		Timestamp: big.NewInt(int64(1)),
		Address:   common.HexToAddress("1"),
		Topics:    make([]common.Hash, 1),
		Data:      []byte{1}}

	//testing ToBytes()
	bz = make([]byte, 0)
	for i := 1; i <= 2; i++ {
		bz = append(bz, append(make([]byte, 31), 1)...)
	}
	bz = append(bz, append(make([]byte, 19), 1)...)
	bz = append(bz, append(make([]byte, 32), 1)...)
	require.Equal(t, bz, logInfo.ToBytes())

	//EthCallInfo and ToBytes() testing
	ethCallInfo := EthCallInfo{
		ChainId:          big.NewInt(int64(1)),
		Timestamp:        big.NewInt(int64(1)),
		From:             common.HexToAddress("1"),
		To:               common.HexToAddress("1"),
		FunctionSelector: [4]byte{1},
		OutData:          []byte{1}}

	//testing ToBytes()
	bz = make([]byte, 0)
	for i := 1; i <= 2; i++ {
		bz = append(bz, append(make([]byte, 31), 1)...)
	}
	for i := 1; i <= 2; i++ {
		bz = append(bz, append(make([]byte, 19), 1)...)
	}
	bz = append(bz, []byte{1, 0, 0, 0, 1}...)
	require.Equal(t, bz, ethCallInfo.ToBytes())
}

func TestEcdhCache(t *testing.T) {
	//testing NewEcdhCache
	cache := NewEcdhCache(4)
	Cache := cache.m
	Cache[[33]byte{0}] = []byte{0}
	Cache[[33]byte{1}] = []byte{1}
	Cache[[33]byte{2}] = []byte{2}
	Cache[[33]byte{3}] = []byte{3}

	value, _ := cache.GetSecret([33]byte{0})
	require.Equal(t, value, []byte{0})
	value, _ = cache.GetSecret([33]byte{1})
	require.Equal(t, value, []byte{1})
	value, _ = cache.GetSecret([33]byte{2})
	require.Equal(t, value, []byte{2})
	value, _ = cache.GetSecret([33]byte{3})
	require.Equal(t, value, []byte{3})

	//Adding new cache entry for PeerKeyToSecret
	var entry [33]byte
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	copy(entry[:], []byte{2, 200, 150, 130, 184, 13, 227, 251, 1, 183, 165, 244, 153, 114, 55, 102, 219, 37, 147, 181, 218, 56, 138, 49, 220, 214, 153, 157, 124, 255, 75, 216, 79})
	value, _ = cache.PeerKeyToSecret(priv, entry, EncapsulateSecret)

	//Checking the value/secret for the new cache entry whether its correct
	senderPubKey, _ := ecies.NewPublicKeyFromBytes(entry[:])
	secret, _ := toEciesPrivKey(priv).Encapsulate(senderPubKey)
	value, _ = cache.GetSecret(entry)
	require.Equal(t, value, secret)

	//testing SetMforUT
	cache.m[[33]byte{0}] = []byte{0}
	cache.SetMForUT([33]byte{0}, []byte{1})
	require.Equal(t, cache.m[[33]byte{0}], []byte{1})
}

func TestRandReader(t *testing.T) {
	//RandReader Part
	rdm := NewRandReader()
	rdm.Read([]byte{1})
	rdm.Read32()
	rdm.GenerateKey()

	//Check decrypted text with original text
	cryptor := NewCryptor([]byte{0}, []byte{0})
	msg := []byte("The quick brown fox jumped over the lazy dog.")
	ciphertext, _ := cryptor.EncryptAesGcm(msg)
	plaintext, _ := cryptor.DecryptAesGcm(ciphertext)
	require.Equal(t, msg, []byte(string(plaintext)))

	//coverage for error parts
	crypto1 := Cryptor{key: nil, nonce: nil}
	ciphertext, _ = crypto1.EncryptAesGcm(msg)
	plaintext, _ = crypto1.DecryptAesGcm(ciphertext)
	require.Equal(t, []byte{}, []byte(string(plaintext)))
}

func TestCbc(t *testing.T) {
	var msg0, msg1 [128]byte
	for i := range msg0 {
		msg0[i] = byte(i)
		msg1[i] = byte(i)
	}
	cryptor := NewCryptor([]byte{0}, []byte{0})
	msg2, err := cryptor.EncryptAesCbc(msg1[:])
	require.Nil(t, err)
	msg3, err := cryptor.DecryptAesCbc(msg2)
	require.Nil(t, err)
	require.Equal(t, len(msg2), len(msg1))
	require.Equal(t, msg0[:], msg3[:])
	require.Equal(t, msg0, msg1)
}

func TestEncryptDecryptMessageWithNewNonce(t *testing.T) {
	encryptionBz, nonceBz, err := EncryptMessageWithNewNonce(token, []byte("test"))
	require.Nil(t, err)
	require.NotEmpty(t, encryptionBz)
	require.NotEmpty(t, nonceBz)

	decryptedBz, err := DecryptMessageWithNonce(token, encryptionBz, nonceBz)
	require.Nil(t, err)
	require.Equal(t, decryptedBz, []byte("test"))
}
