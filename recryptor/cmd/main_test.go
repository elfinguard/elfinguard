package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elfinguard/elfinguard/recryptor/constants"
	"github.com/elfinguard/elfinguard/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

var sampleEncryptToken string = "AZ4Rk11PvkaG8prjMRebKjL4ncoPu572hdVfBngaJmQF8m7sJoBYYewWkyBfz5tHQEHysQwadwb3orHntPtXTTNy3TJKRofrBzeBAPTaFkuYfdRo7FceHqDMdGfeVQCmCyh9JahPf4D3qXrryZ8X63tb9qS5Aqn73cp943jSdua49GCQxXdx3RZ7Ky8kEVYa8gUFmMEpvsZ7DGw"
var sampleDecryptToken string = "Ka254SbxWBzKCBoY49dkbEiPM2TzGJG4zhTRfSaq1nkHi8xg1uPthohj2188VPZC2fgFYav5khzfmM7c7FkjsH8qqA35tT3sFjZbfVTCyTEurNSdhHjs7E8wnnmcGiJcPQe1jBZ1DSACGQj1T9n9z4vxnETAktGqUFHu6ycqtVSGvoXj88PxtWm5fN5d9EZD7DECPjqXnMMV2NExHMwT6pdyYitYTWXkys8afiNVDXNoa8q4YZrzgh387eh4Rk8Q"
var PUBKEY = []byte{2, 200, 150, 130, 184, 13, 227, 251, 1, 183, 165, 244, 153, 114, 55, 102, 219, 37, 147, 181, 218, 56, 138, 49, 220, 214, 153, 157, 124, 255, 75, 216, 79}
var dgSample = types.DecryptionGuide{
	ChainId:        big.NewInt(100000000),
	Contract:       "trial",
	Function:       "hello",
	Threshold:      2,
	AuthorizerList: []string{"A"},
	EncryptedParts: [][]byte{{1}},
	CallDataList:   [][]byte{{28, 138, 255, 149, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
	Signature:      []byte{1, 23, 3},
	Timestamp:      time.Now().Unix(),
	RecryptorSalt:  []byte{1},
	FileId:         []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
}

var egSample = types.EncryptionGuide{
	ChainId:        big.NewInt(1),
	Contract:       "hello",
	Function:       "hello",
	Threshold:      2,
	AuthorizerList: []string{"a", "b"},
	OutData:        []byte{1},
}

var encryptTokenSample = types.EncryptTaskToken{
	ExpireTime:    time.Now().Unix() + 100,
	FileId:        [32]byte{1},
	RecryptorSalt: [32]byte{1},
	Secret:        [32]byte{1, 2, 3, 4, 5},
	RequestorAddr: [20]byte{1, 2},
}

var decryptTokenSample = types.DecryptTaskToken{
	ExpireTime:    time.Now().Unix() + 100,
	FileId:        [32]byte{1},
	RecryptorSalt: [32]byte{1},
	Secret:        [32]byte{1},
	RemoteAddr:    "localhost",
	ViewerAccount: [20]byte{1},
	Contract:      "test",
}

type myCG struct {
	chunk      []byte
	totalBytes int
}

func (cg myCG) GetChunk(token types.DecryptTaskToken, path string, index int) (chunk []byte, errStr string) {
	var msg [128]byte // It's size must be 16*N
	for i := range msg {
		msg[i] = byte(i)
	}
	encryption, _ := encryptChunk(encryptTokenSample, msg[:], 1)
	return encryption, ""
}
func (cg myCG) GetTotalBytes(path string) (totalBytes int, errStr string) {
	return 5, ""
}

func GetGrantCodesForTest(authorizers []string, timestamp int64, contract [20]byte, sig, outData []byte, callDataList [][]byte) (requestorAddr [20]byte, codes [][]byte, errList []error) {
	return [20]byte{1, 2}, [][]byte{{1}, {2}}, []error{nil, nil}
}

func decryptChunkForTest(token types.DecryptTaskToken, chunk []byte, index int) ([]byte, error) {
	return []byte{1, 5}, nil
}

func CheckDecryptTaskForTest(ip string, token types.DecryptTaskToken) error {
	return nil
}

func getAuthResultForTest(url string) (result types.AuthResult) {
	salt := make([]byte, 8)
	binary.LittleEndian.PutUint64(salt, uint64(time.Now().Unix()+600))
	var pubkey [33]byte
	EcdhCache = types.NewEcdhCache(1)
	copy(pubkey[:], PUBKEY)
	PrivKey = types.NewKeyFile("./key.txt").RecoveryPrivateKey(true)
	ecdhSecret, _ := EcdhCache.PeerKeyToSecret(PrivKey, pubkey, types.DecapsulateSecret)
	cryptor := types.NewCryptor(salt, ecdhSecret)
	encryption, _ := cryptor.EncryptAesGcm([]byte{1})
	res := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	copy(res[20:], encryption)
	return types.AuthResult{
		Succeeded: true,
		Message:   "message",
		Result:    res,
		Proof:     []byte{1},
		Salt:      salt,
		PubKey:    PUBKEY,
	}
}

func SetupRouter() *gin.Engine {
	router := gin.Default()
	return router
}

func getRemoteReportTest(bytes []byte) ([]byte, error) {
	return []byte{1}, nil
}

func TestGetPubkeyReportFunc(t *testing.T) {
	getRemoteReport = getRemoteReportTest
	router := SetupRouter()
	router.GET("/pubkey_report", getPubkeyReportFunc)
	req, _ := http.NewRequest("GET", "/pubkey_report", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	mockResponse := `{"result":"0x01","success":true}`
	require.Equal(t, mockResponse, string(responseData))
	require.Equal(t, 200, w.Code)
}

func TestGetPubkeyFunc(t *testing.T) {
	router := SetupRouter()
	router.GET("/pubkey", getPubkeyFunc)
	req, _ := http.NewRequest("GET", "/pubkey", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	mockResponse := `{"result":"0x000000000000000000000000000000000000000000000000000000000000000000","success":true}`
	require.Equal(t, mockResponse, string(responseData))
	require.Equal(t, 200, w.Code)
}

func TestPingFunc(t *testing.T) {
	getRemoteReport = getRemoteReportTest
	router := SetupRouter()
	router.GET("/eg_ping", pingFunc)
	req, _ := http.NewRequest("GET", "/eg_ping", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	mockResponse := `{"isSuccess":true,"message":"pong"}`
	require.Equal(t, mockResponse, string(responseData))
	require.Equal(t, 200, w.Code)
}

func TestEncryptDecryptChunk(t *testing.T) {
	// encryptChunk and decryptChunk
	var msg [128]byte // It's size must be 16*N
	for i := range msg {
		msg[i] = byte(i)
	}
	encryption, _ := encryptChunk(encryptTokenSample, msg[:], 3)
	decryption, _ := decryptChunk(decryptTokenSample, encryption, 3)
	require.Equal(t, decryption, msg[:])

	//encryptChunk larger than 256*1024
	longMsg := make([]byte, 262145)
	long, _ := encryptChunk(encryptTokenSample, longMsg, 3)
	decryption, _ = decryptChunk(decryptTokenSample, long, 3)
	require.Equal(t, decryption, []byte(nil))

	//COMBINE AND SPLIT
	//try if part and threshold==1
	splitByte, _ := split([]byte{0}, 1, 1)
	combineByte, _ := combine(splitByte, 1)
	require.Equal(t, combineByte, []byte{0})

	//try if part and threshold>1
	splitByte, _ = split([]byte{0, 1, 2, 3, 4}, 3, 2)
	combineByte, _ = combine(splitByte, 4)
	require.Equal(t, combineByte, []byte{0, 1, 2, 3, 4})
}

func TestGetEncryptTaskTokenFunc(t *testing.T) {
	sig := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3}
	signature, _ := secp256k1.Sign(sig, sig)
	queryParms := url.Values{"sig": []string{hex.EncodeToString(signature)}, "fileId": []string{"1"}}
	qAppendedURL := "/eg_getEncryptTaskToken" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("GET", qAppendedURL, nil)
	router := SetupRouter()
	router.GET("/eg_getEncryptTaskToken", getEncryptTaskTokenFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	require.Equal(t, 200, w.Code)
	require.NotEmpty(t, responseData)
}

func TestGetEncryptTaskTokenListFunc(t *testing.T) {
	sig := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3}
	signature, _ := secp256k1.Sign(sig, sig)
	queryParms := url.Values{"sig": []string{hex.EncodeToString(signature)}, "fileIds": []string{"1,2"}}
	qAppendedURL := "/eg_getEncryptTaskTokenList" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("GET", qAppendedURL, nil)
	router := SetupRouter()
	router.GET("/eg_getEncryptTaskTokenList", getEncryptTaskTokenListFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	require.Equal(t, 200, w.Code)
	require.NotEmpty(t, responseData)
}

func TestGetEncryptedParts(t *testing.T) {
	//Testing getEncryptedParts
	getGrantCodes = GetGrantCodesForTest
	token := encryptTokenSample
	eg := egSample
	_, err := getEncryptedParts(token, eg)
	require.Equal(t, err, nil)
}

func TestEncryptChunkOnServerFunc(t *testing.T) {
	queryParms := url.Values{"index": []string{"1"}, "token": []string{sampleEncryptToken}}
	qAppendedURL := "/eg_encryptChunkOnServer" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("POST", qAppendedURL, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	router := SetupRouter()
	router.POST("/eg_encryptChunkOnServer", encryptChunkOnServerFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	require.Equal(t, 200, w.Code)
	require.Empty(t, responseData)
}

func TestEncryptChunkFunc(t *testing.T) {
	queryParms := url.Values{"index": []string{"1"}, "token": []string{sampleEncryptToken}}
	qAppendedURL := "/eg_encryptChunk" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("POST", qAppendedURL, bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	router := SetupRouter()
	router.POST("/eg_encryptChunk", encryptChunkFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	require.Equal(t, 200, w.Code)
	require.Empty(t, responseData)
}

func TestGetApis(t *testing.T) {
	AllowedApis = "eg_ping"
	require.Equal(t, getApis(), []string{constants.APIPing})
}

func TestFindMatchingApis(t *testing.T) {
	AllowedApis = "eg_ping"
	require.Equal(t, []string{"eg_ping"}, findMatchingApis([]string{AllowedApis}, AvailableApis))
}
func TestGetDecryptTaskToken(t *testing.T) {
	getGrantCodes = GetGrantCodesForTest
	salt := append([]byte{1}, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}...)
	cryptor1 := types.NewCryptor(salt, []byte{1})
	cryptor2 := types.NewCryptor(salt, []byte{2})
	parts1, _ := cryptor1.EncryptAesGcm([]byte{1})
	parts2, _ := cryptor2.EncryptAesGcm([]byte{2})
	dg := dgSample
	dg.Threshold = 1
	dg.EncryptedParts = [][]byte{parts1, parts2}
	dg2 := dg
	remoteAddr := "localhost:8080"
	_, err := getDecryptTaskToken(dg2, remoteAddr)
	require.Equal(t, nil, err)
}

func TestGetDecryptTaskTokenFunc(t *testing.T) {
	//Testing for GetDecryptTaskTokenFunc
	getGrantCodes = GetGrantCodesForTest
	salt := append([]byte{1}, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}...)
	cryptor1 := types.NewCryptor(salt, []byte{1})
	cryptor2 := types.NewCryptor(salt, []byte{2})
	parts1, _ := cryptor1.EncryptAesGcm([]byte{1})
	parts2, _ := cryptor2.EncryptAesGcm([]byte{2})
	dg := dgSample
	dg.Threshold = 1
	dg.EncryptedParts = [][]byte{parts1, parts2}

	getGrantCodes = GetGrantCodesForTest
	queryParms := url.Values{"index": []string{"3"}, "token": []string{sampleDecryptToken}}
	qAppendedURL := "/eg_getDecryptTaskToken" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("POST", qAppendedURL, nil)
	bz, _ := json.Marshal(dg)
	req.Body = io.NopCloser(bytes.NewReader(bz)) //
	router := SetupRouter()
	router.POST("/eg_getDecryptTaskToken", getDecryptTaskTokenFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	require.Equal(t, 200, w.Code)
	require.NotEmpty(t, responseData)
}

func TestCheckDecryptTask(t *testing.T) {
	token := decryptTokenSample
	token.RemoteAddr = "test"
	require.Equal(t, checkDecryptTask("test", token), nil)
}

func TestDecryptedFileChunk(t *testing.T) {
	DecryptChunk = decryptChunkForTest
	_oldCG := ChunkGetter
	ChunkGetter = myCG{
		chunk:      []byte{1, 2, 3},
		totalBytes: 3,
	}
	defer func() { ChunkGetter = _oldCG }()
	chunk, errStr := getDecryptedChunk(decryptTokenSample, "test", 1)
	require.Equal(t, errStr, "")
	require.Equal(t, chunk, []byte{1, 5})
}

func TestGetGrantCodes(t *testing.T) {
	GetAuthResult = getAuthResultForTest
	dg := dgSample
	requestAddr, codes, _ := GetGrantCodes(dg.AuthorizerList, dg.Timestamp, common.HexToAddress(dg.Contract), dg.Signature, nil, dg.CallDataList)
	require.Equal(t, requestAddr, [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	require.Equal(t, codes, [][]byte{{1}})
}

func TestGetGrantCode(t *testing.T) {
	GetAuthResult = getAuthResultForTest
	dg := dgSample
	requestorAddr, code, _ := GetGrantCode(dg.AuthorizerList[0], dg.Timestamp, [20]byte{1}, dg.Signature, dg.CallDataList[0], "1", 1)
	require.Equal(t, requestorAddr, [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	require.Equal(t, code, []byte{1})
}

func TestDecryptChunkFunc(t *testing.T) {
	CheckDecryptTask = CheckDecryptTaskForTest
	DecryptChunk = decryptChunkForTest
	_oldCG := ChunkGetter
	ChunkGetter = myCG{
		chunk:      []byte{1, 2, 3},
		totalBytes: 3,
	}
	defer func() { ChunkGetter = _oldCG }()

	queryParms := url.Values{"index": []string{"3"}, "token": []string{sampleDecryptToken}}
	qAppendedURL := "/eg_decryptChunk" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("POST", qAppendedURL, nil)
	bz, _ := json.Marshal(dgSample)
	req.Body = io.NopCloser(bytes.NewReader(bz))
	router := SetupRouter()
	router.POST("eg_decryptChunk", decryptChunkFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	response, _ := io.ReadAll(w.Body)
	require.Equal(t, 200, w.Code)
	require.NotEmpty(t, response)
}

func TestGetDecryptedFileFunc(t *testing.T) {
	CheckDecryptTask = CheckDecryptTaskForTest
	_oldCG := ChunkGetter
	ChunkGetter = myCG{
		chunk:      []byte{1, 2, 3},
		totalBytes: 10,
	}
	defer func() { ChunkGetter = _oldCG }()
	queryParms := url.Values{"size": []string{"5"}, "path": []string{"test"}, "index": []string{"1"}, "token": []string{sampleDecryptToken}}
	qAppendedURL := "/eg_getDecryptedFile/:text.txt" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("GET", qAppendedURL, nil)
	bz, _ := json.Marshal(dgSample)
	req.Body = io.NopCloser(bytes.NewReader(bz))
	req.RemoteAddr = "localhost:8080"
	req.Header.Set("Range", "bytes=0-0")
	router := SetupRouter()
	router.GET("eg_getDecryptedFile/:file", getDecryptedFileFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	responseData, _ := io.ReadAll(w.Body)
	require.Equal(t, 206, w.Code)
	require.NotEmpty(t, responseData)
	require.Equal(t, responseData, []byte{1})
}

func TestGetEncryptedPartsFunc(t *testing.T) {
	//First retrieve most updated encryptTaskTokenFirst
	sig := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3}
	signature, _ := secp256k1.Sign(sig, sig)
	queryParms := url.Values{"sig": []string{hex.EncodeToString(signature)}, "fileId": []string{"1"}}
	qAppendedURL := "/eg_getEncryptTaskToken" + "?" + queryParms.Encode()
	req, _ := http.NewRequest("GET", qAppendedURL, nil)
	router := SetupRouter()
	router.GET("/eg_getEncryptTaskToken", getEncryptTaskTokenFunc)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	responseData, _ := io.ReadAll(w.Body)
	test := strings.Split(string(responseData), `","recryptorsalt`)[0]
	token := strings.Split(string(test), `task_token":"`)[1]

	//testing for getEncryptedParts
	getGrantCodes = GetGrantCodesForTest
	queryParms = url.Values{"token": []string{token}}
	qAppendedURL = "/eg_getEncryptedParts" + "?" + queryParms.Encode()
	router = SetupRouter()
	router.POST("/eg_getEncryptedParts", getEncryptedPartsFunc)
	w = httptest.NewRecorder()
	//w.Header().Set("Content-Type", "application/json; charset=utf-8")
	eg := types.EncryptionGuide{
		ChainId:        big.NewInt(1),
		Contract:       "test",
		Function:       "test",
		Threshold:      2,
		AuthorizerList: []string{"a", "b"},
		OutData:        []byte{1},
	}
	bz, _ := json.Marshal(eg)
	req, _ = http.NewRequest("POST", qAppendedURL, bytes.NewBuffer(bz))
	router.ServeHTTP(w, req)

	responseData, _ = io.ReadAll(w.Body)
	require.Equal(t, 200, w.Code)
	require.NotEmpty(t, responseData)
}

func TestMaxMin(t *testing.T) {
	testMax := max(1, 2)
	require.Equal(t, testMax, 2)
	testMax = max(2, 1)
	require.Equal(t, testMax, 2)

	testMin := min(1, 2)
	require.Equal(t, testMin, 1)
	testMin = min(2, 1)
	require.Equal(t, testMin, 1)
}
