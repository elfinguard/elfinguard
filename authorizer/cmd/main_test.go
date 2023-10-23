package main

import (
	// "net/url"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	// "encoding/hex"
	"encoding/json"
	// "io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"

	// "strconv"
	// "strings"
	"testing"
	"time"

	"github.com/edgelesssys/ego/attestation"
	"github.com/elfinguard/elfinguard/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// *****MOCK DECLARATIONS*****

func testDialContext(ctx context.Context, rawurl string) (Web3Client, error) {
	return MockWeb3Client{}, nil
}

func testHttpGet(url string, usingHttps bool) []byte {
	switch url {
	case "example.com/sgx_report":
		return []byte("3131313131313131313131313131313131313131313131313131313131313131,3131313131313131313131313131313131313131313131313131313131313131")
	default:
		return nil
	}
}

type MockWeb3Client struct {
}

func (_ MockWeb3Client) HeaderByNumber(ctx context.Context, number *big.Int) (*ethtypes.Header, error) {
	header := ethtypes.Header{
		ParentHash:  common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		UncleHash:   common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		Coinbase:    common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		Root:        common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		TxHash:      common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		ReceiptHash: common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		Bloom:       ethtypes.BytesToBloom([]byte{0, 0, 0, 0, 0, 0, 0, 0}),
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(0),
		GasLimit:    uint64(0),
		GasUsed:     uint64(0),
		Time:        uint64(0),
		Extra:       []byte{},
		MixDigest:   common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		Nonce:       ethtypes.BlockNonce{0, 0, 0, 0, 0, 0, 0, 0},
	}

	return &header, nil
}

func (_ MockWeb3Client) BlockNumber(ctx context.Context) (uint64, error) {
	return 20, nil
}

func (_ MockWeb3Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	// callcontract makes "eth_call" call
	var hex hexutil.Bytes
	hex, _ = hexutil.Uint(0).MarshalText()

	return hex, nil
}

func (_ MockWeb3Client) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]ethtypes.Log, error) {
	// CallContext calls "eth_getLogs"
	log := ethtypes.Log{
		Address:     common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		Topics:      []common.Hash{common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}},
		Data:        []byte{},
		BlockNumber: 5,
		TxHash:      common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		TxIndex:     uint(10),
		BlockHash:   common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
		Index:       uint(0),
		Removed:     false,
	}

	return []ethtypes.Log{log}, nil
}

func (_ MockWeb3Client) TransactionByHash(ctx context.Context, hash common.Hash) (tx *ethtypes.Transaction, isPending bool, err error) {
	legacyTx := ethtypes.LegacyTx{
		Nonce:    uint64(10000),
		GasPrice: big.NewInt(1000),
		Gas:      uint64(1000),
		To:       &common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		Value:    big.NewInt(10000),
		Data:     []byte{},
		V:        big.NewInt(27),
		R:        big.NewInt(10000),
		S:        big.NewInt(10000),
	}

	result := ethtypes.NewTx(&legacyTx)

	return result, false, nil
}

func (_ MockWeb3Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*ethtypes.Receipt, error) {
	r := ethtypes.Receipt{
		Type:              uint8(2),
		PostState:         []byte{},
		Status:            uint64(1),
		CumulativeGasUsed: uint64(100),
		Bloom:             ethtypes.Bloom{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		Logs:              []*ethtypes.Log{},
		TxHash:            common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		ContractAddress:   common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		GasUsed:           uint64(100),
		BlockHash:         common.Hash{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		BlockNumber:       big.NewInt(1),
		TransactionIndex:  1,
	}

	return &r, nil
}

func (_ MockWeb3Client) Close() {
}

// added for test mocking enclave pkg
func testVerifyRemoteReportFn(reportBytes []byte) (attestation.Report, error) {
	report := attestation.Report{
		Data:            []byte{138, 131, 102, 95, 55, 152, 114, 127, 20, 249, 42, 208, 230, 201, 159, 218, 176, 142, 231, 49, 214, 205, 100, 76, 19, 18, 35, 253, 47, 79, 237, 42},
		SecurityVersion: 3,
		Debug:           false,
		UniqueID:        []byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
		SignerID:        []byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
		ProductID:       []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	return report, nil
}

// *****TEST FUNCTIONS*****

func TestAuthorizer(t *testing.T) {
	keySharingHandshake()
}

func getRemoteReportTest(bytes []byte) ([]byte, error) {
	return []byte{0}, nil
}

func TestPingFunc(t *testing.T) {
	r := gin.Default()
	r.GET("/eg_ping", pingFunc)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/eg_ping", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var res map[string]interface{}
	err := json.Unmarshal([]byte(w.Body.String()), &res)
	if err != nil {
		t.Errorf("expected error to be nil but got %v", err)
	}

	fmt.Println(res)

	require.Equal(t, res["message"], "pong")
}

func TestTxFunc(t *testing.T) {
	_rpcClient.dialContext = testDialContext

	ChainId = big.NewInt(int64(10000))
	RpcUrlList = []string{"rpcurl1.com", "rpcurl2.com", "rpcurl3.com"}

	r := gin.Default()
	r.GET("/eg_tx", getTxFunc)
	w := httptest.NewRecorder()

	req, _ := http.NewRequest(
		"GET",
		"/eg_tx?hash=0x48ce6d72fcb0f83129262ee56ce29f553d17510141c44f631678f21cd81ea29b",
		nil,
	)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var res map[string]interface{}
	err := json.Unmarshal([]byte(w.Body.String()), &res)
	if err != nil {
		t.Errorf("expected error to be nil but got %v", err)
	}

	require.Equal(t, res["result"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANhlhPUDfgNzNOagmHiAqX6zCyjRkIawN68GWE0+gQbhmLiY96SJ1NSXOxkPHFii1APPrSwAAQIDBAUGBwgJCgsMDQ4PEBESEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACcQ")
}

func TestLogFunc(t *testing.T) {
	_rpcClient.dialContext = testDialContext
	ChainId = big.NewInt(int64(10000))

	r := gin.Default()
	r.GET("/eg_log", getLogFunc)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(
		"GET",
		"/eg_log?block=0x33a8d7d8c00886287626b9bc58a3f113df2759767ec291282832e10faffd49d2&contract=0x77cb87b57f54667978eb1b199b28a0db8c8e1c0b&topic0=0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef&topic1=0x00000000000000000000000002343cb5d5d470f571b0e7c48d029ce4dc4bb5bb&topic2=0x0000000000000000000000000d4372acc0503fbcc7eb129e0de3283c348b82c3&topic3=0x00000000000000000000000000000000000000000000000e227bf02fc1976ebd",
		nil,
	)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestCallFunc(t *testing.T) {
	_rpcClient.dialContext = testDialContext
	ChainId = big.NewInt(int64(10000))
	RpcUrlList = []string{"rpcurl1.com", "rpcurl2.com", "rpcurl3.com"}

	r := gin.Default()
	r.GET("/eg_call", getCallFunc)

	w := httptest.NewRecorder()

	req, _ := http.NewRequest(
		"GET",
		"/eg_call?contract=8342bde992f79988d6e228451d6595c7227fbfe9&from=0x84d8CD2cC6C22189dbf42e2B2Bf20E5a27137606&data=1111",
		nil,
	)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestGetPubkeyFunc(t *testing.T) {
	r := gin.Default()
	r.GET("/pubkey", getPubkeyFunc)
	req, _ := http.NewRequest("GET", "/pubkey", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var res map[string]interface{}
	err := json.Unmarshal([]byte(w.Body.String()), &res)
	if err != nil {
		t.Errorf("expected error to be nil but got %v", err)
	}

	require.Equal(t, res["success"], true)
	// require.Equal(t, res["result"], "0x03d45c7077945b0ff9124b9c10b0f1bf9504d9986df76ac19079ebb8341f1ad0d1")
	require.Equal(t, res["result"], "0x")
}

func TestGetPubkeyReportFunc(t *testing.T) {
	getRemoteReport = getRemoteReportTest

	r := gin.Default()
	r.GET("/pubkey_report", getPubkeyReportFunc)
	req, _ := http.NewRequest("GET", "/pubkey_report", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var res map[string]interface{}
	err := json.Unmarshal([]byte(w.Body.String()), &res)
	if err != nil {
		t.Errorf("expected error to be nil but got %v", err)
	}

	require.Equal(t, res["success"], true)
	require.Equal(t, res["result"], "0x00")
}

func TestVerifyKeyReceiver(t *testing.T) {
	_rpcClient.dialContext = testDialContext
	httpGet = testHttpGet
	verifyRemoteReportFn = testVerifyRemoteReportFn
	PubKeyBz = []byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49}

	peerPubkeyBytes := verifyKeyReceiver(
		"example.com",
		[]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
		[]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
	)

	require.Equal(t, peerPubkeyBytes, []byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49})
}

func TestVerifyReport(t *testing.T) {
	verifyRemoteReportFn = testVerifyRemoteReportFn

	err := verifyReport(
		[]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
		[]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
		[]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
		[]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
	)

	require.Nil(t, err)
}

func TestGetGrantCode(t *testing.T) {
	PrivKey = types.NewKeyFile("./key.txt").RecoveryPrivateKey(false)
	ChainId = big.NewInt(int64(10000))
	PubKeyBz = []byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49}

	_rpcClient.dialContext = testDialContext

	var res types.AuthResult

	res = GetGrantCode(
		int64(time.Now().Unix()),
		common.Address{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		"1",
		[][]byte{{1, 1, 1, 1}, {1, 1, 1, 1}},
		1,
		[]byte{1},
		[]byte{},
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
	)

	require.NotEmpty(t, res)
	require.True(t, res.Succeeded)
}

func TestSignBytes(t *testing.T) {
	msg := []byte("message")
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// privKey is nil
	sig, err := signBytes(msg, nil)
	require.Nil(t, sig)

	// privKey is not nil
	// check that there's no error signing
	sig, err = signBytes(msg, privKey)
	require.Nil(t, err)
}

func TestGetFromAllServers(t *testing.T) {
	RpcUrlList = []string{"rpcurl1.com", "rpcurl2.com", "rpcurl3.com"}
	getter := func(rpcUrl string) ([]byte, error) {
		return []byte{1}, nil
	}

	res, _ := getFromAllServers(getter)

	require.Equal(t, len(res), 1)
	require.Equal(t, res[0], uint8(1))
}

func TestVerifyReceiversAndSendKey(t *testing.T) {
	EcdhCache = types.NewEcdhCache(2000)
	httpGet = testHttpGet
	verifyRemoteReportFn = testVerifyRemoteReportFn
	PrivKey = types.NewKeyFile("./key.txt").RecoveryPrivateKey(false)
	SignerID = []byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49}

	// add a key-value pair to EcdhCache's m
	EcdhCache.SetMForUT(
		[33]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 0},
		[]byte{115, 101, 99, 114, 101, 116},
	)

	verifyReceiversAndSendKey(
		"example.com",
		[]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
	)
}

//
// BELOW HERE GOT SOME ERRORS
//
/*
func TestKeyFunc(t *testing.T) {
	EcdhCache = types.NewEcdhCache(2000)
	EcdhCache.SetMForUT(
		// [33]byte{49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49},
		[33]byte{6, 63, 172, 146, 1, 73, 79, 11, 209, 123, 152, 146, 185, 250, 228, 213, 47, 227, 189, 55, 115, 33, 50, 67, 36, 35, 66, 52, 50, 50, 52, 35, 36},
		[]byte{115, 101, 99, 114, 101, 116},
	)
	dialContext = testDialContext
	ChainId = big.NewInt(int64(10000))
	RpcUrlList = []string{"rpcurl1.com", "rpcurl2.com", "rpcurl3.com"}

	// EcdhCache.SetMForUT(
	// 	[33]byte{54, 51, 70, 97, 67, 57, 50, 48, 49, 52, 57, 52, 102, 48, 98, 100, 49, 55, 66, 57, 56, 57, 50, 66, 57, 102, 97, 101, 52, 100, 53, 50, 102},
	// 	[]byte{114, 101, 112, 111, 114, 116},
	// )

	r := gin.Default()
	r.GET("/eg_key", getKeyFunc)
	w := httptest.NewRecorder()

	// IsKeySource is true
	IsKeySource = true
	req, _ := http.NewRequest(
		"GET",
		"/eg_key?k=0x63FaC9201494f0bd17B9892B9fae4d52fe3BD3773213243242342343232342324,0x21a5cda47239bc803de08e0bd1e20b049f351b15e5b5ee78741510ccbbf63b2da88741b9e8e5fcc447190688c748d5ac",
		nil,
	)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)

	// set IsKeySource back to false
	IsKeySource = false
	// PrivKey is not nil
	PrivKey = types.NewKeyFile("./data/key.txt").RecoveryPrivateKey(true)
	// PrivKey = types.NewKeyFile("./data/key.txt").RecoveryPrivateKey(false)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)


	// WORKS UP TO HERE***************

	// set PrivKey back to nil

	PrivKey = nil
	PubKeyBz = []byte{6, 63, 172, 146, 1, 73, 79, 11, 209, 123, 152, 146, 185, 250, 228, 213, 47, 227, 189, 55, 115, 33, 50, 67, 36, 35, 66, 52, 50, 50, 52, 35, 36}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	fmt.Println("****CODE333", w.Code)
	fmt.Println(w)
	require.Equal(t, http.StatusOK, w.Code)

}

func TestGrantCodeFunc(t *testing.T) {
	// need types import
	//EcdhCache = types.NewEcdhCache(*cacheSize)
	// genKeys()

	dialContext = testDialContext
	// PrivKey = types.NewKeyFile("key.txt").RecoveryPrivateKey(true)

	r := gin.Default()
	r.GET("/eg_grantcode", getGrantcodeFunc)
	w := httptest.NewRecorder()
	queryTime := strconv.FormatInt(time.Now().Unix()-100, 10)
	targetStr := "/eg_grantcode?contract=0x77cb87b57f54667978eb1b199b28a0db8c8e1c0b&datalist=1111111111111111&nth=1&out=1111&sig=0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101&time=" + queryTime + "&recryptorpk=1111"
	req, _ := http.NewRequest(
		"GET",
		targetStr,
		nil,
	)

	r.ServeHTTP(w, req)

	// fmt.Println("W IS", w)

	require.Equal(t, http.StatusOK, w.Code)
}
*/
