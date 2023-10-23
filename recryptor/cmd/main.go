package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	gethcmn "github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/vault/shamir"
	"github.com/mr-tron/base58"
	"github.com/qingstor/go-mime"
	log "github.com/sirupsen/logrus"
	"github.com/smartbch/egvm/keygrantor"

	"github.com/elfinguard/elfinguard/certs"
	"github.com/elfinguard/elfinguard/recryptor/chunkgetter"
	"github.com/elfinguard/elfinguard/recryptor/constants"
	"github.com/elfinguard/elfinguard/recryptor/request"
	"github.com/elfinguard/elfinguard/recryptor/response"
	"github.com/elfinguard/elfinguard/recryptor/router"
	"github.com/elfinguard/elfinguard/recryptor/websocket"
	"github.com/elfinguard/elfinguard/types"
)

const (
	HttpsCertFile         = "./key/cert.pem"
	EncryptedHttpsKeyFile = "./key/encryptedKey.txt"
	DecryptedHttpsKeyFile = "./key/decryptedKey.pem"
	ChunkFileDir          = "./storage"
)

var (
	EnableTLS     bool              // Enable TLS (serve https instead of http)
	ListenAddr    string            // IP address and port
	PrivKey       *ecdsa.PrivateKey // for secure communication and identification (each recryptor has its unique Key)
	KeyGrantor    string            // The key grantor's hostname(or ip) and port, seperated by colon
	PubKeyHex     string
	PubKeyBz      [33]byte
	ReportBz      []byte           // Attestation report which endorses PrivKey
	EcdhCache     *types.EcdhCache // map publicKey of Auth Proxy to shared secrets
	HttpClient    *http.Client
	ChunkGetter   types.ChunkGetter
	ProxyDomain   string
	AllowedApis   string
	AvailableApis = []string{constants.APIPing, constants.APIGetEncryptTaskToken, constants.APIGetEncryptTaskTokenList, constants.APIGetEncryptedParts,
		constants.APIEncryptChunk, constants.APIEncryptChunkOnServer, constants.APIGetDecryptTaskToken, constants.APIDecryptChunk, constants.APIGetDecryptedFile, constants.APIPubkey, constants.APIPubkeyReport, constants.APICert, constants.APICertReport}

	AttestationProviderURL string
	RateLimiter            types.RateLimiter
	CheckDecryptTask       func(ip string, token types.DecryptTaskToken) error                                                                                                                  = checkDecryptTask
	GetAuthResult          func(url string) (result types.AuthResult)                                                                                                                           = getAuthResult
	getGrantCodes          func(authorizers []string, timestamp int64, contract [20]byte, sig, outData []byte, callDataList [][]byte) (requestorAddr [20]byte, codes [][]byte, errList []error) = GetGrantCodes
	DecryptChunk           func(token types.DecryptTaskToken, chunk []byte, index int) ([]byte, error)                                                                                          = decryptChunk
	getRemoteReport        func(reportBytes []byte) (report []byte, err error)                                                                                                                  = enclave.GetRemoteReport
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "gen-cert-files" {
		certs.GenCertFiles(true)
		return
	}

	initLogger()
	parseFlags()
	genEnclaveKeysAndGetReports()
	if EnableTLS {
		createAndStartHttpsServer()
		return
	}
	createAndStartHttpServer()
}

func parseFlags() {
	flag.BoolVar(&EnableTLS, "tls", true, "use TLS or not")
	cacheSize := flag.Int("cache", 2000, "size of the ecdh cache")
	flag.StringVar(&AllowedApis, "apis", "*", "listen address")
	EcdhCache = types.NewEcdhCache(*cacheSize)
	flag.StringVar(&ListenAddr, "listen-addr", "0.0.0.0:8881", "listen address")
	rpcAddr := flag.String("rpc", "0.0.0.0:8022", "grpc server address")
	flag.StringVar(&AttestationProviderURL, "attestation", "https://shareduks.uks.attest.azure.net", "attestation provider's URL")
	flag.StringVar(&ProxyDomain, "proxy", "", "A proxy to Elfin authorizers")
	keyGrantor := flag.String("key-grantor", "", "key grantor's hostname(or ip) and port, seperated by colon")
	flag.Parse()

	HttpClient = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   3 * time.Second,
	}

	//ChunkGetter = newGrpcChunkGetter(rpcAddr)
	//ChunkGetter = newRpcxChunkGetter(rpcAddr)
	ChunkGetter = chunkgetter.NewKuboChunkGetter(*rpcAddr) //just used for debug
	KeyGrantor = *keyGrantor
}

func genEnclaveKeysAndGetReports() {
	PrivKey = getKeyFromKG(KeyGrantor)
	copy(PubKeyBz[:], gethcrypto.CompressPubkey(&PrivKey.PublicKey))
	pubKeyHash := sha256.Sum256(PubKeyBz[:])
	PubKeyHex = hex.EncodeToString(PubKeyBz[:])
	var err error
	ReportBz, err = enclave.GetRemoteReport(pubKeyHash[:])
	if err != nil {
		panic(err)
	}

	log.Infof("Recryptor PubKeyBz: %v", gethcmn.Bytes2Hex(PubKeyBz[:]))
}

func getKeyFromKG(keyGrantor string) *ecdsa.PrivateKey {
	bip32Key, err := keygrantor.GetKeyFromKeyGrantor(keyGrantor, [32]byte{})
	if err != nil {
		log.Fatal("failed to get key from grantor", err)
	}
	ecdsaKey, err := gethcrypto.ToECDSA(bip32Key.Key)
	if err != nil {
		log.Fatal("failed to convert key", err)
	}
	return ecdsaKey
}

func initLogger() {
	log.SetFormatter(&log.TextFormatter{
		ForceQuote:      true,
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
}

func createAndStartHttpServer() {
	ginRouter := router.SetupRouter(constants.MaxMemForParsing)
	initHttpHandlers(ginRouter)
	initWsHandlers(ginRouter)

	server := &http.Server{
		Addr:    ListenAddr,
		Handler: ginRouter,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("listen error: %v", err)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, os.Kill)
	<-quit
	log.Println("shutdown server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Errorf("shutdown err: %v", err)
	}
}

func createAndStartHttpsServer() {
	ginRouter := router.SetupRouter(constants.MaxMemForParsing)
	initHttpHandlers(ginRouter)
	initWsHandlers(ginRouter)

	certificate, err := certs.LoadCertAndEncryptedKey(HttpsCertFile, EncryptedHttpsKeyFile)
	if err != nil {
		log.Errorf("Failed to load encrypted https key and certificate: %v", err)
		return
	}

	server := &http.Server{
		Addr:      ListenAddr,
		Handler:   ginRouter,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Errorf("listen error: %v", err)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, os.Kill)
	<-quit
	log.Println("shutdown server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Errorf("shutdown err: %v", err)
	}
}

func initHttpHandlers(router gin.IRouter) {
	for _, handlers := range getApis() {
		switch handlers {
		case constants.APIPing:
			router.GET("/eg_ping", pingFunc)
		case constants.APIGetEncryptTaskToken:
			router.GET("/eg_getEncryptTaskToken", getEncryptTaskTokenFunc)
		case constants.APIGetEncryptTaskTokenList:
			router.GET("/eg_getEncryptTaskTokenList", getEncryptTaskTokenListFunc)
		case constants.APIGetEncryptedParts:
			router.POST("/eg_getEncryptedParts", getEncryptedPartsFunc)
		case constants.APIEncryptChunk:
			router.POST("/eg_encryptChunk", encryptChunkFunc)
		case constants.APIEncryptChunkOnServer:
			router.POST("/eg_encryptChunkOnServer", encryptChunkOnServerFunc)
		case constants.APIGetDecryptTaskToken:
			router.POST("/eg_getDecryptTaskToken", getDecryptTaskTokenFunc)
		case constants.APIDecryptChunk:
			router.POST("/eg_decryptChunk", decryptChunkFunc)
		case constants.APIGetDecryptedFile:
			router.GET("/eg_getDecryptedFile/:file", getDecryptedFileFunc)
		case constants.APIPubkey:
			router.GET("/pubkey", getPubkeyFunc)
		case constants.APIPubkeyReport:
			router.GET("/pubkey_report", getPubkeyReportFunc)
		case constants.APICert:
			router.GET("/cert", getCertFunc)
		case constants.APICertReport:
			router.GET("/cert_report", getCertReportFunc)
		default:
			continue
		}
	}
}

func initWsHandlers(router gin.IRouter) {
	hub := websocket.NewHub()
	go hub.Run()

	router.GET("/ws", func(c *gin.Context) {
		websocket.ServeWs(hub, c)
	})
}

func getPubkeyReportFunc(c *gin.Context) {
	pbkHash := sha256.Sum256(PubKeyBz[:])
	//report, err := enclave.GetRemoteReport(pbkHash[:])
	report, err := getRemoteReport(pbkHash[:])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"result":  "0x" + hex.EncodeToString(report),
	})
}

func getPubkeyFunc(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"result":  "0x" + hex.EncodeToString(PubKeyBz[:]),
	})
}

func getCertFunc(c *gin.Context) {
	certificate, err := certs.LoadCertAndEncryptedKey(HttpsCertFile, EncryptedHttpsKeyFile)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	cert := certificate.Certificate[0]
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"result":  "0x" + hex.EncodeToString(cert),
	})
}

func getCertReportFunc(c *gin.Context) {
	certificate, err := certs.LoadCertAndEncryptedKey(HttpsCertFile, EncryptedHttpsKeyFile)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	cert := certificate.Certificate[0]
	certHash := sha256.Sum256(cert)
	report, err := getRemoteReport(certHash[:])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"result":  "0x" + hex.EncodeToString(report),
	})
}

func pingFunc(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"isSuccess": true,
		"message":   "pong",
	})
}

// Before an author encrypts a file, she must get an EncryptTaskToken from a recryptor
func getEncryptTaskTokenFunc(c *gin.Context) {
	req := &request.GetEncryptTaskTokenReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	if RateLimiter != nil && !RateLimiter.CanServe(c.ClientIP(), c.Request.URL.Path, c.Request.URL.RawQuery, nil, nil) {
		c.String(http.StatusTooManyRequests, "")
		return
	}

	bz, _ := req.EncryptTaskToken.MarshalMsg(nil)
	bz, err = ecrypto.SealWithUniqueKey(bz, nil)
	if err != nil {
		log.Errorf("failed to seal with unique key: %v", err)
		c.String(http.StatusInternalServerError, "failed to seal with unique key: %v", err)
		return
	}

	result := &response.GetEncryptTaskTokenResp{
		EncryptTaskToken: base58.Encode(bz),
		Recryptorsalt:    base64.StdEncoding.EncodeToString(req.EncryptTaskToken.RecryptorSalt[:]),
		Pubkey:           base64.StdEncoding.EncodeToString(PubKeyBz[:]),
	}
	c.JSON(http.StatusOK, result)
}

func getEncryptTaskTokenListFunc(c *gin.Context) {
	req := &request.GetEncryptTaskTokenListReq{}

	if RateLimiter != nil && !RateLimiter.CanServe(c.ClientIP(), c.Request.URL.Path, c.Request.URL.RawQuery, nil, nil) {
		c.String(http.StatusTooManyRequests, "")
		return
	}

	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	results := make([]*response.GetEncryptTaskTokenResp, 0, len(req.EncryptTaskTokenList))
	for _, token := range req.EncryptTaskTokenList {
		bz, _ := token.MarshalMsg(nil)
		bz, err := ecrypto.SealWithUniqueKey(bz, nil)
		if err != nil {
			log.Errorf("failed to seal with unique key: %v", err)
			c.String(http.StatusInternalServerError, "failed to seal with unique key: %v", err)
			return
		}

		results = append(results, &response.GetEncryptTaskTokenResp{
			EncryptTaskToken: base58.Encode(bz),
			Recryptorsalt:    base64.StdEncoding.EncodeToString(token.RecryptorSalt[:]),
			Pubkey:           base64.StdEncoding.EncodeToString(PubKeyBz[:]),
		})
	}
	c.JSON(http.StatusOK, results)
}

// With an EncryptTaskToken and EncryptionGuide, query the authorizers to get EncryptedParts
func getEncryptedPartsFunc(c *gin.Context) {
	req := &request.GetEncryptedPartsReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	if RateLimiter != nil {
		bz, _ := io.ReadAll(c.Request.Body)
		if !RateLimiter.CanServe(c.ClientIP(), c.Request.URL.Path, c.Request.URL.RawQuery, req.TokenBzBase58, bz) {
			c.String(http.StatusTooManyRequests, "")
			return
		}
	}

	encryptedParts, err := getEncryptedParts(req.EncryptTaskToken, req.EncryptionGuide)
	if err != nil {
		log.Errorf("failed to get encryptedParts: %v", err)
		c.String(http.StatusBadRequest, "failed to get encryptedParts: %v", err)
		return
	}

	c.JSON(http.StatusOK, encryptedParts)
}

// With an EncryptTaskToken, encrypt a chunk of the original file
func encryptChunkFunc(c *gin.Context) {
	encryptChunkHandler(c, false)
}

func encryptChunkOnServerFunc(c *gin.Context) {
	encryptChunkHandler(c, true)
}

func encryptChunkHandler(c *gin.Context, saveOnServer bool) {
	req := &request.EncryptOrDecryptChunkReq{IsEncrypt: true}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	if RateLimiter != nil && !RateLimiter.CanServe(c.ClientIP(), c.Request.URL.Path, c.Request.URL.RawQuery, req.TokenBzBase58, nil) {
		c.String(http.StatusTooManyRequests, "")
		return
	}

	chunk, err := encryptChunk(req.EncryptTaskToken, req.Chunk, req.Index)
	if err != nil {
		log.Errorf("encrypt chunk err: %v", err)
		c.String(http.StatusBadRequest, "encrypt chunk err: %v", err)
		return
	}

	if saveOnServer {
		err = writeChunk(req.EncryptTaskToken, chunk, req.Index)
		if err != nil {
			log.Errorf("write chunk err: %v", err)
			c.String(http.StatusInternalServerError, "write chunk err: %v", err)
			return
		}
	}

	c.String(http.StatusOK, "")
}

// Before a viewer decrypts a file, she must get a DecryptTaskToken from a recryptor
func getDecryptTaskTokenFunc(c *gin.Context) {
	req := &request.GetDecryptedPartsReq{}
	if err := req.Bind(c); err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	if RateLimiter != nil {
		bz, _ := io.ReadAll(c.Request.Body)
		if !RateLimiter.CanServe(c.ClientIP(), c.Request.URL.Path, c.Request.URL.RawQuery, nil, bz) {
			c.String(http.StatusTooManyRequests, "")
			return
		}
	}

	ip := c.ClientIP()
	token, err := getDecryptTaskToken(req.DecryptionGuide, ip)
	if err != nil {
		log.Errorf("failed to get DecryptTaskToken: %v", err)
		c.String(http.StatusBadRequest, "failed to get DecryptTaskToken: %v", err)
		return
	}

	bz, _ := token.MarshalMsg(nil)
	bz, err = ecrypto.SealWithUniqueKey(bz, nil)
	if err != nil {
		log.Errorf("failed to seal with unique key: %v", err)
		c.String(http.StatusInternalServerError, "failed to seal with unique key: %v", err)
		return
	}

	result := &response.GetDecryptTaskTokenResp{
		DecryptTaskToken: base58.Encode(bz),
		Pubkey:           base64.StdEncoding.EncodeToString(PubKeyBz[:]),
	}
	c.JSON(http.StatusOK, result)
}

// With a DecryptTaskToken, a viewer require recryptor to decrypt the POST body.
func decryptChunkFunc(c *gin.Context) {
	req := &request.EncryptOrDecryptChunkReq{IsEncrypt: false}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	if RateLimiter != nil && !RateLimiter.CanServe(c.ClientIP(), c.Request.URL.Path, c.Request.URL.RawQuery, req.TokenBzBase58, nil) {
		c.String(http.StatusTooManyRequests, "")
		return
	}

	ip := c.ClientIP()
	err = CheckDecryptTask(ip, req.DecryptTaskToken)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	chunk, err := DecryptChunk(req.DecryptTaskToken, req.Chunk, req.Index)
	if err != nil {
		log.Errorf("decryptChunk err: %v", err)
		c.String(http.StatusBadRequest, "decryptChunk err: %v", err)
		return
	}

	c.String(http.StatusOK, string(chunk))
}

// With a DecryptTaskToken, a viewer require recryptor to decrypt an IPFS file. Resuming breakpoints is supported
func getDecryptedFileFunc(c *gin.Context) {
	req := &request.GetDecryptedFileReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	if RateLimiter != nil && !RateLimiter.CanServe(c.ClientIP(), c.Request.URL.Path, c.Request.URL.RawQuery, req.TokenBzBase58, nil) {
		c.String(http.StatusTooManyRequests, "")
		return
	}

	ip := c.ClientIP()
	err = CheckDecryptTask(ip, req.DecryptTaskToken)
	if err != nil {
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	totalBytes, errStr := ChunkGetter.GetTotalBytes(req.Path)
	if errStr != "" {
		log.Errorf("ipfs get total bytes err: %v", errStr)
		c.String(http.StatusInternalServerError, "ipfs get total bytes err: %v", errStr)
		return
	}

	if totalBytes > req.Size {
		totalBytes = req.Size
	}

	if totalBytes == 0 {
		c.String(http.StatusNoContent, "")
		return
	}

	var start, end int
	rangeReq := c.GetHeader("Range")
	if len(rangeReq) > 0 {
		c.Status(http.StatusPartialContent)

		rangeReq = strings.TrimPrefix(rangeReq, "bytes=")
		startAndEnd := strings.Split(rangeReq, "-")
		if len(startAndEnd) != 2 {
			c.String(http.StatusBadRequest, "invalid range header")
			return
		}

		rangeStart, err := strconv.Atoi(startAndEnd[0])
		if err != nil && startAndEnd[0] != "" {
			c.String(http.StatusBadRequest, "invalid range start")
			return
		}

		if startAndEnd[0] == "" {
			rangeStart = 0
		}

		rangeEnd, err := strconv.Atoi(startAndEnd[1])
		if err != nil && startAndEnd[1] != "" {
			c.String(http.StatusBadRequest, "invalid range end")
			return
		}

		if startAndEnd[1] == "" {
			rangeEnd = totalBytes - 1
		}

		start = max(0, rangeStart)
		end = max(0, min(totalBytes, rangeEnd+1))

		if end <= start || rangeEnd+1 > totalBytes {
			c.String(http.StatusRequestedRangeNotSatisfiable, "invalid range period or exceeds total bytes")
			return
		}
	} else {
		// without range
		c.Status(http.StatusOK)
		end = totalBytes
	}

	// if range > 512KB
	if end-start > 2*constants.ChunkSize {
		end = start + 2*constants.ChunkSize
	}

	mimeType := mime.DetectFilePath(req.FileName)
	c.Header("Content-Type", mimeType)
	c.Header("Content-Length", fmt.Sprintf("%d", end-start))
	c.Header("Accept-Ranges", "bytes")
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end-1, totalBytes))

	for start < end {
		index := start / constants.ChunkSize
		chunk, errStr := getDecryptedChunk(req.DecryptTaskToken, req.Path, index)
		if len(errStr) != 0 {
			c.Status(http.StatusBadRequest)
			_, err := c.Writer.WriteString(errStr)
			if err != nil {
				log.Errorf("write error message err: %v", err)
			}
			break
		}

		chunkStart, chunkEnd := start%constants.ChunkSize, constants.ChunkSize

		// if last chunk
		if end < (index+1)*constants.ChunkSize {
			chunkEnd = end % constants.ChunkSize
		}

		_, err := c.Writer.Write(chunk[chunkStart:chunkEnd])
		if err != nil {
			log.Errorf("write chunk err: %v", err)
			break
		}
		start = (index + 1) * constants.ChunkSize
	}
}

// ----------------------------------------------------------------------------

// From an authorizer, get the authorization result which contains the grantcode
func getAuthResult(url string) (result types.AuthResult) {
	req, err := http.NewRequest(http.MethodGet, url, bytes.NewReader(ReportBz))
	if err != nil {
		panic(err)
	}

	resp, err := HttpClient.Do(req)
	if err != nil {
		result.Message = err.Error()
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			result.Message = fmt.Sprintf("getAuthResult status code: %d, but failed to decode body", resp.StatusCode)
			return
		}

		result.Message = fmt.Sprintf("getAuthResult status code: %d, error message: %+v", resp.StatusCode, result)
		return
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		result.Message = "failed to decode body"
		return
	}
	return
}

// From an authorizer, get the grantcode which is encrypted using the Salt and ecdhSecret
func GetGrantCode(authorizer string, timestamp int64, contract [20]byte, sig, outData []byte,
	callDataListStr string, nth int) (requestorAddr [20]byte, code []byte, err error) {
	if len(ProxyDomain) != 0 {
		authorizer = ProxyDomain + "/" + authorizer
	}

	url := fmt.Sprintf("https://%s/eg_grantcode?time=%d&contract=0x%s&datalist=%s&nth=%d&recryptorpk=0x%s",
		authorizer, timestamp, hex.EncodeToString(contract[:]), callDataListStr, nth, PubKeyHex)
	if len(outData) != 0 { // for authors' encryption
		url += fmt.Sprintf("&out=0x%s", hex.EncodeToString(outData))
	} else { // for audience's decryption
		url += fmt.Sprintf("&sig=0x%s", hex.EncodeToString(sig))
	}
	result := GetAuthResult(url)
	if !result.Succeeded {
		return requestorAddr, nil, errors.New(result.Message)
	}
	resultTime := int64(binary.LittleEndian.Uint64(result.Salt[:8]))
	now := time.Now().Unix()
	if resultTime < now-constants.MaxTimeDifference || now+constants.MaxTimeDifference < resultTime {
		return requestorAddr, nil, errors.New("time difference is too large")
	}

	var peerPubkey [33]byte
	copy(peerPubkey[:], result.PubKey)
	log.Infof("authorizer pubkey: %v", gethcmn.Bytes2Hex(result.PubKey))
	ecdhSecret, err := EcdhCache.PeerKeyToSecret(PrivKey, peerPubkey, types.DecapsulateSecret)
	if err != nil {
		return requestorAddr, nil, err
	}

	cryptor := types.NewCryptor(result.Salt, ecdhSecret)
	code, err = cryptor.DecryptAesGcm(result.Result[20:])
	if err != nil {
		log.Errorf("decrypt aes failed: %v", err)
		return requestorAddr, nil, err
	}
	copy(requestorAddr[:], result.Result[:20])
	return
}

// From several authorizers, get the grantcodes
func GetGrantCodes(authorizers []string, timestamp int64, contract [20]byte, sig, outData []byte,
	callDataList [][]byte) (requestorAddr [20]byte, codes [][]byte, errList []error) {
	codes = make([][]byte, len(authorizers))
	errList = make([]error, len(authorizers))
	addrList := make([][20]byte, len(authorizers))
	var wg sync.WaitGroup
	wg.Add(len(authorizers))

	var cdSb strings.Builder
	for i, cd := range callDataList {
		cdSb.WriteString(hex.EncodeToString(cd))
		if i < len(callDataList)-1 {
			cdSb.WriteString(",")
		}
	}

	hexCallData := cdSb.String()

	for index := range authorizers {
		go func(i int) {
			addrList[i], codes[i], errList[i] = GetGrantCode(authorizers[i], timestamp,
				contract, sig, outData, hexCallData, i)
			wg.Done()
		}(index)
	}
	wg.Wait()
	for i, addr := range addrList {
		if errList[i] == nil {
			requestorAddr = addr
		}
	}
	return
}

func getEncryptedParts(token types.EncryptTaskToken, eg types.EncryptionGuide) (encryptedParts [][]byte, err error) {
	now := time.Now().Unix()
	if now > token.ExpireTime {
		return nil, errors.New("the EncryptTaskToken is expired")
	}

	parts, err := split(token.Secret[:], len(eg.AuthorizerList), eg.Threshold)
	if err != nil {
		return nil, err
	}

	encryptedParts = make([][]byte, len(eg.AuthorizerList))
	callDataList := make([][]byte, len(eg.AuthorizerList))
	hash := gethcrypto.Keccak256([]byte(eg.Function))
	for i := range callDataList {
		callDataList[i] = hash[:4] // only the function selector
	}
	_, codes, errList := getGrantCodes(eg.AuthorizerList, now, gethcmn.HexToAddress(eg.Contract), nil, eg.OutData, callDataList)
	for i, code := range codes {
		if errList[i] != nil { // We must get all of the grantcodes
			return nil, errList[i]
		}
		salt := append(token.RecryptorSalt[:], token.FileId[:]...)
		cryptor := types.NewCryptor(salt, code)
		var err error
		encryptedParts[i], err = cryptor.EncryptAesGcm(parts[i])
		if err != nil {
			return nil, err
		}
	}
	return encryptedParts, nil
}

func encryptChunk(token types.EncryptTaskToken, chunk []byte, index int) ([]byte, error) {
	if len(chunk) > constants.ChunkSize {
		return nil, errors.New("chunk is too large")
	}

	var indexBz [8]byte
	binary.LittleEndian.PutUint64(indexBz[:], uint64(index))
	salt := append(append(indexBz[:], token.RecryptorSalt[:]...), token.FileId[:]...)
	cryptor := types.NewCryptor(salt, token.Secret[:])
	return cryptor.EncryptAesCbc(chunk)
}

func writeChunk(token types.EncryptTaskToken, chunk []byte, index int) error {
	fileName := hex.EncodeToString(token.RecryptorSalt[:])
	filePath := path.Join(ChunkFileDir, fileName)
	var fileSize int64
	fi, err := os.Stat(filePath)
	if err == nil {
		fileSize = fi.Size()
	} else if os.IsNotExist(err) {
		fileSize = 0
	} else {
		return err
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	offset := int64(index * constants.ChunkSize)
	if fileSize+constants.MaxSkippedChunk*constants.ChunkSize < offset {
		return errors.New("too many skipped chunks")
	}
	_, err = f.WriteAt(chunk, offset)
	return err
}

func getDecryptTaskToken(dg types.DecryptionGuide, remoteAddr string) (token types.DecryptTaskToken, err error) {
	hash := gethcrypto.Keccak256([]byte(dg.Function))
	for _, callData := range dg.CallDataList {
		if len(callData) < 68 {
			return token, errors.New("CallData Is Too Short")
		}
		if !bytes.Equal(hash[:4], callData[:4]) {
			return token, errors.New("CallData's Function Selector is incorrect")
		}
		if !bytes.Equal(dg.FileId[:], callData[36:68]) {
			return token, errors.New("CallData's second parameter is not FileId")
		}
	}
	requestorAddr, codes, errList := getGrantCodes(dg.AuthorizerList, dg.Timestamp,
		gethcmn.HexToAddress(dg.Contract), dg.Signature, nil, dg.CallDataList)
	okCount := 0
	parts := make([][]byte, len(codes))
	var errStr string
	for i, code := range codes { // use the grantcodes for the shamir-split parts' decryption
		if errList[i] != nil {
			errStr += dg.AuthorizerList[i] + ": " + errList[i].Error() + "\n"
			continue
		}
		okCount++
		salt := append(dg.RecryptorSalt, dg.FileId[:]...)
		cryptor := types.NewCryptor(salt, code)
		var err error
		parts[i], err = cryptor.DecryptAesGcm(dg.EncryptedParts[i])
		if err != nil {
			parts[i] = nil
			errStr += err.Error()
			return token, errors.New(errStr)
		}
	}
	if okCount < dg.Threshold {
		errStr += fmt.Sprintf("Only got %d grantcode. We need %d.", okCount, dg.Threshold)
		return token, errors.New(errStr)
	}
	secret, err := combine(parts, dg.Threshold) // the original secret before shamir-splitting is recovered
	if err != nil {
		errStr += err.Error()
		return token, errors.New(errStr)
	}
	copy(token.Secret[:], secret)
	token.ExpireTime = dg.Timestamp + constants.MaxDecryptionDuration
	token.ViewerAccount = requestorAddr
	copy(token.FileId[:], dg.FileId)
	copy(token.RecryptorSalt[:], dg.RecryptorSalt)
	token.RemoteAddr = remoteAddr
	token.Contract = dg.Contract
	return token, nil
}

func decryptChunk(token types.DecryptTaskToken, chunk []byte, index int) ([]byte, error) {
	var indexBz [8]byte
	binary.LittleEndian.PutUint64(indexBz[:], uint64(index))
	salt := append(append(indexBz[:], token.RecryptorSalt[:]...), token.FileId[:]...)
	cryptor := types.NewCryptor(salt, token.Secret[:])
	chunk, err := cryptor.DecryptAesCbc(chunk)
	return chunk, err
}

func checkDecryptTask(ip string, token types.DecryptTaskToken) error {
	if time.Now().Unix() > token.ExpireTime {
		return errors.New("the DecryptTaskToken is expired")
	}
	if ip != token.RemoteAddr {
		return errors.New("invalid IP for this token")
	}
	return nil
}

func getDecryptedChunk(token types.DecryptTaskToken, path string, index int) (chunk []byte, errStr string) {
	copiedToken := token            //make a copy
	copiedToken.Secret = [32]byte{} //clear the secret
	chunk, errStr = ChunkGetter.GetChunk(copiedToken, path, index)
	if len(errStr) != 0 {
		return
	}
	chunk, err := DecryptChunk(token, chunk, index)
	if err != nil {
		return nil, err.Error()
	}
	return chunk, ""
}

// shamir.Combine only allows 2~256 parts. We need to support len(parts)==1
func combine(parts [][]byte, threshold int) ([]byte, error) {
	if len(parts) == 1 || threshold == 1 {
		for _, part := range parts {
			if len(part) != 0 {
				return part, nil
			}
		}
	}
	return shamir.Combine(parts)
}

// shamir.Split only allows 2~256 parts. We need to support parts==1
func split(secret []byte, parts, threshold int) ([][]byte, error) {
	if parts == 1 || threshold == 1 {
		res := make([][]byte, parts)
		for i := 0; i < threshold; i++ {
			res[i] = secret
		}
		return res, nil
	}
	return shamir.Split(secret, parts, threshold)
}

func getApis() []string {
	if len(AllowedApis) == 0 {
		panic("invalid APIs specified")
	}
	if AllowedApis == "*" {
		return AvailableApis
	}

	return findMatchingApis(strings.Split(AllowedApis, ","), AvailableApis)
}

func findMatchingApis(allowedApis, availableApis []string) []string {
	if len(allowedApis) > len(availableApis) {
		panic("too many APIs inputted")
	}

	availableApisSet := make(map[string]struct{}, len(availableApis))
	for _, x := range availableApis {
		availableApisSet[x] = struct{}{}
	}

	match := make([]string, 0, len(availableApis))
	for _, x := range allowedApis {
		if _, found := availableApisSet[x]; found {
			match = append(match, x)
			continue
		}
		// panic if mismatch found
		panic("one or more APIs inputted is/are not available")
	}
	return match
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
