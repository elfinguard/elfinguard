package main

import (
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/assert"
)

func ReadSessionIdParamForTest(w http.ResponseWriter, query map[string][]string) (bz []byte, ok bool) {
	return []byte{1}, true
}

func TestReadStringParam(t *testing.T) {
	w := httptest.NewRecorder()
	query := make(map[string][]string)
	query["key1"] = []string{"a"}
	query["key2"] = []string{"b", "b"}

	// key with one value
	param, ok := readStringParam(w, query, "key1")
	assert.Equal(t, param, "a")
	assert.True(t, ok)

	// key with more than one value
	param, ok = readStringParam(w, query, "key2")
	assert.Equal(t, param, "")
	assert.False(t, ok)

	// key with no value
	param, ok = readStringParam(w, query, "key3")
	assert.Equal(t, param, "")
	assert.False(t, ok)
}

func TestReadHexParam(t *testing.T) {
	w := httptest.NewRecorder()
	query := make(map[string][]string)
	str1 := "hello"
	str2 := "bye"
	value1 := hex.EncodeToString([]byte(str1))
	value2 := hex.EncodeToString([]byte(str2))
	query["key1"] = []string{"0x" + value1}
	query["key2"] = []string{"0x" + value1, "0x" + value2}
	query["key3"] = []string{"0x111"}

	// key with one value
	param, ok := readHexParam(w, query, "key1")
	param1, _ := hex.DecodeString(value1)
	assert.Equal(t, param, param1)
	assert.True(t, ok)

	// key with more than one value
	param, ok = readHexParam(w, query, "key2")
	assert.Nil(t, param)
	assert.False(t, ok)

	// key with one value that causes cannot decode error
	param, ok = readHexParam(w, query, "key3")
	assert.Nil(t, param)
	assert.False(t, ok)

	// key with no value
	param, ok = readHexParam(w, query, "key4")
	assert.Nil(t, param)
	assert.True(t, ok)
}

func TestGetNonceFunc(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/eg_getNonce", nil)
	w := httptest.NewRecorder()
	getNonceFunc(w, req)
	res := w.Result()
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	assert.NotEmpty(t, data)
	assert.Nil(t, err)

	nonce := w.Body.String()
	w = httptest.NewRecorder()
	query := make(map[string][]string)
	query["nonce"] = []string{nonce}
	_, ok := readNonceParam(w, query)
	assert.Equal(t, ok, true)
}

func TestGetRecryptorFunc(t *testing.T) {
	ReadSessionIdParam = ReadSessionIdParamForTest
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/eg_test", nil)
	getRecryptorFunc(w, r)
	res := w.Result()
	defer res.Body.Close()
	_, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil but got %v", err)
	}
}
func TestGetProxyFunc(t *testing.T) {
	ReadSessionIdParam = ReadSessionIdParamForTest
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/eg_test", nil)
	getProxyFunc(w, r)

	res := w.Result()
	defer res.Body.Close()
	_, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil but got %v", err)
	}
}

func TestRecoverSender(t *testing.T) {
	//retrieve the nonce first
	req := httptest.NewRequest(http.MethodGet, "/eg_getNonce", nil)
	w := httptest.NewRecorder()
	getNonceFunc(w, req)
	nonce := w.Body.String()

	//testing recoverSender
	w = httptest.NewRecorder()
	query := make(map[string][]string)
	a := []byte{8, 2, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3, 1, 2, 89, 4, 5, 6, 7, 8, 9, 7, 8, 12, 13, 13, 13, 99}
	sig, _ := secp256k1.Sign(a, a)
	value2 := hex.EncodeToString(sig)
	query["sig"] = []string{"0x" + value2}
	query["nonce"] = []string{nonce}
	_, ok := recoverSender(w, query)
	assert.Equal(t, ok, true)
}

func TestSessionIDFunc(t *testing.T) {
	//retrieve the nonce first
	req := httptest.NewRequest(http.MethodGet, "/eg_getNonce", nil)
	w := httptest.NewRecorder()
	getNonceFunc(w, req)
	nonce := w.Body.String()

	//testing GetSessionIdFunc
	a := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 1, 2, 3}
	sig, _ := secp256k1.Sign(a, a)
	w = httptest.NewRecorder()
	queryParms := url.Values{"nonce": []string{nonce}, "sig": []string{hex.EncodeToString(sig)}}
	qAppendedURL := "https://www.example.com/path1/path2" + "?" + queryParms.Encode()
	r, _ := http.NewRequest(http.MethodGet, qAppendedURL, nil)
	getSessionIDFunc(w, r)

	res := w.Result()
	defer res.Body.Close()
	_, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("expected error to be nil but got %v", err)
	}

	//testing TestReadSessionIdParam
	session := w.Body.String()
	w = httptest.NewRecorder()
	query := make(map[string][]string)
	query["session"] = []string{session}
	_, ok := readSessionIdParam(w, query)
	assert.Equal(t, ok, true)

	//testing edge cases for wrong Hmac signature
	session_hmacWrong := "2d7da8eb821d6a03d5f5cb509bfda5b72b3fe29d185565ca00f1cbbfd49799632d7da8eb821d6a03d5f5cb509bfd5555"
	w = httptest.NewRecorder()
	query = make(map[string][]string)
	query["session"] = []string{session_hmacWrong}
	_, ok = readSessionIdParam(w, query)
	assert.Equal(t, ok, false)

	//testing edge cases for len(bz)<48
	w = httptest.NewRecorder()
	query = make(map[string][]string)
	query["session"] = []string{"0x" + hex.EncodeToString([]byte{1})}
	_, ok = readSessionIdParam(w, query)
	assert.Equal(t, ok, false)
}
