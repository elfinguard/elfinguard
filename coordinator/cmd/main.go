package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	shell "github.com/ipfs/go-ipfs-api"
	log "github.com/sirupsen/logrus"

	"github.com/elfinguard/elfinguard/certs"
	"github.com/elfinguard/elfinguard/coordinator/constants"
	"github.com/elfinguard/elfinguard/coordinator/request"
	"github.com/elfinguard/elfinguard/coordinator/router"
	"github.com/elfinguard/elfinguard/coordinator/util"
)

const (
	HttpsCertFile         = "./key/cert.pem"
	DecryptedHttpsKeyFile = "./key/decryptedKey.pem"
	ChunkFileDir          = "../file"
)

var (
	EnableTLS       bool // Enable TLS (serve https instead of http)
	ListenAddr      string
	IpfsDaemonAddr  string
	HmacKey         []byte
	MyDomain        string
	ProxyDomain     string
	RecryptorDomain string
	RecryptorDir    string
	DirectoryPrefix string
	IpfsShell       *shell.Shell
	IpfsDirNumber   int64
)

func main() {
	initLogger()
	parseFlags()

	if EnableTLS {
		createAndStartHttpsServer()
		return
	}
	createAndStartHttpServer()
}

func initLogger() {
	log.SetFormatter(&log.TextFormatter{
		ForceQuote:      true,
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
}

func parseFlags() {
	flag.BoolVar(&EnableTLS, "tls", true, "use TLS or not")
	flag.StringVar(&ListenAddr, "listen-addr", "0.0.0.0:8082", "listen address")
	flag.StringVar(&IpfsDaemonAddr, "ipfs-daemon", "0.0.0.0:5001", "IPFS's daemon's address and port")
	flag.StringVar(&MyDomain, "domain", "", "Domain name of this coordinator")
	flag.StringVar(&ProxyDomain, "proxy", "", "The proxy to the authorizers")
	flag.StringVar(&RecryptorDomain, "recryptor", "", "The only recryptor's domain name (this demo only supports one recryptor)")
	flag.StringVar(&RecryptorDir, "recryptor-dir", ChunkFileDir, "The recryptor's working directory")
	flag.StringVar(&DirectoryPrefix, "prefix", "elfinhost", "the prefix of temporary directories")
	key := flag.String("hmac", "", "HMAC Key for generating nonces and signing session IDs")
	flag.Parse()

	IpfsShell = shell.NewShell(IpfsDaemonAddr)
	IpfsDirNumber = time.Now().UnixNano()
	var err error
	HmacKey, err = hex.DecodeString(*key)
	if err != nil {
		panic(err)
	}
}

func createAndStartHttpServer() {
	ginRouter := router.SetupRouter(constants.MaxMemForParsing)
	initHttpHandlers(ginRouter)

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
	//err := endless.ListenAndServe(ListenAddr, ginRouter)

	certificate, err := certs.LoadCertAndDecryptedKey(HttpsCertFile, DecryptedHttpsKeyFile)
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
	router.GET("/eg_getNonce", getNonceFunc)
	router.GET("/eg_getSessionID", getSessionIDFunc)
	router.GET("/eg_getRecryptor", getRecryptorFunc)
	router.GET("/eg_getProxy", getProxyFunc)
	router.GET("/eg_getFile", getFileFunc)
	router.POST("/eg_upload", uploadFunc)
}

// getNonce
// nonce format: bytes0:12 is random data, bytes12:16 is timestamp, bytes16:32 is hmac signature
func getNonceFunc(c *gin.Context) {
	nonce, err := genNonce(HmacKey)
	if err != nil {
		log.Errorf("get nonce err: %v", err)
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	c.String(http.StatusOK, hex.EncodeToString(nonce))
}

// eg_getSessionID?sig=<hex-encoded-signature>&nonce=<nonce>
// SessionID format: bytes0:20 is sender address, bytes28:32 is timestamp, bytes32:48 is hmac signature, other is random data
func getSessionIDFunc(c *gin.Context) {
	req := &request.GetSessionIDReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	err = validateNonce(req.NonceBz, HmacKey, constants.NonceDuration)
	if err != nil {
		log.Errorf("validate nonce bz err: %v", err)
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	sender, err := util.RecoverSender(req.SigBz, req.NonceBz, MyDomain)
	if err != nil {
		log.Errorf("recover sender err: %v", err)
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	sessionId, err := genSessionID(HmacKey, sender)
	if err != nil {
		log.Errorf("gen sessionId err: %v", err)
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	c.String(http.StatusOK, hex.EncodeToString(sessionId))
}

// eg_getRecryptor?session=<session-id>
func getRecryptorFunc(c *gin.Context) {
	req := &request.GetRecryptorOrAuthorizerReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "invalid parameters")
		return
	}

	err = validateSessionID(req.SessionBz, HmacKey, constants.MaxSessionDuration)
	if err != nil {
		log.Errorf("validate session bz err: %v", err)
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	c.String(http.StatusOK, RecryptorDomain)
}

// eg_getProxy?session=<session-id>
func getProxyFunc(c *gin.Context) {
	req := &request.GetRecryptorOrAuthorizerReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	err = validateSessionID(req.SessionBz, HmacKey, constants.MaxSessionDuration)
	if err != nil {
		log.Errorf("validate session bz err: %v", err)
		c.String(http.StatusBadRequest, "validate session bz err: %v", err)
		return
	}

	c.String(http.StatusOK, ProxyDomain)
}

// eg_getFile?path=<path-of-the-file>&session=<session-id>
func getFileFunc(c *gin.Context) {
	req := &request.GetFileReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	err = validateSessionID(req.SessionBz, HmacKey, constants.MaxSessionDuration)
	if err != nil {
		log.Errorf("validate session bz err: %v", err)
		c.String(http.StatusBadRequest, "validate session bz err: %v", err)
		return
	}

	file, err := IpfsShell.Cat(req.Path)
	if err != nil {
		log.Errorf("ipfs client read file failed: %v", err)
		c.String(http.StatusBadRequest, "ipfs client read file failed: %v", err)
		return
	}
	defer file.Close()

	_, err = io.Copy(c.Writer, file)
	if err != nil {
		log.Errorf("transfer failed: %v", err)
		c.String(http.StatusBadRequest, "transfer failed: %v", err)
		return
	}
}

// eg_upload?session=<session-id>&recryptor=<domain-name-of-recryptor>
func uploadFunc(c *gin.Context) {
	req := &request.UploadFileReq{}
	err := req.Bind(c)
	if err != nil {
		log.Errorf("bind request err: %v", err)
		c.String(http.StatusBadRequest, "bind request err: %v", err)
		return
	}

	err = validateSessionID(req.SessionBz, HmacKey, constants.MaxSessionDuration)
	if err != nil {
		log.Errorf("validate session bz err: %v", err)
		c.String(http.StatusBadRequest, "validate session bz err: %v", err)
		return
	}

	// gin parse multipart form
	form, err := c.MultipartForm()
	if err != nil {
		log.Errorf("parse multipart form err: %v", err)
		c.String(http.StatusBadRequest, err.Error())
		return
	}

	dirNum := atomic.AddInt64(&IpfsDirNumber, 1)
	cwd := fmt.Sprintf("/%s-%d", DirectoryPrefix, dirNum)
	err = IpfsShell.FilesMkdir(c, cwd)
	if err != nil {
		log.Errorf("create dir err: %v", err)
		c.String(http.StatusInternalServerError, "create dir err: %v", err)
		return
	}

	for name, value := range form.File {
		var file io.ReadCloser
		if value[0].Size == 0 { // a hex string of recryptorSalt
			file, err = os.Open(path.Join(RecryptorDir, value[0].Filename))
		} else { // a Blob
			file, err = value[0].Open()
		}

		if err != nil {
			log.Errorf("failed to open file: %v", name)
			c.String(http.StatusInternalServerError, "failed to open file: %v", name)
			return
		}
		defer file.Close()

		cid, err := IpfsShell.Add(file)
		if err != nil {
			log.Errorf("failed to add %v: %v", name, err)
			c.String(http.StatusInternalServerError, "failed to add %v: %v", name, err)
			return
		}

		err = IpfsShell.FilesCp(c, fmt.Sprintf("/ipfs/%s", cid), cwd+"/"+name)
		if err != nil {
			log.Errorf("failed to copy %v to ipfs: %v", name, err)
			c.String(http.StatusInternalServerError, "failed to copy %v to ipfs: %v", name, err)
			return
		}
	}

	info, err := IpfsShell.FilesStat(c, cwd)
	if err != nil {
		log.Errorf("failed to check path stat: %v", err)
		c.String(http.StatusInternalServerError, "failed to check path stat: %v", err)
		return
	}

	c.String(http.StatusOK, info.Hash)
}
