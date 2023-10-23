package certs

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/edgelesssys/ego/ecrypto"

	"github.com/elfinguard/elfinguard/types"
)

const (
	EncryptedHttpsKeyFile = "./key/encryptedKey.txt"
	DecryptedHttpsKeyFile = "./key/decryptedKey.pem"
	HttpsCertFile         = "./key/cert.pem"
	EnclaveKeyFile        = "./data/key.txt"
	CsrFile               = "./key/csr.pem"
	CsrDataFile           = "./key/csr_data.json"
	ServerName            = "elfinguard.io"
)

var (
	csrDataFile string
	serverName  string
	bothKept    bool
	helpFlag    bool
)

func GenCertFiles(isEnclaveMode bool) {
	flag.StringVar(&csrDataFile, "csr-data-file", CsrDataFile, "path of CSR data file")
	flag.StringVar(&serverName, "server-name", ServerName, "server name to generate self signed cert")
	flag.BoolVar(&helpFlag, "help", false, "show help")
	flag.BoolVar(&bothKept, "both-kept", false, "both encrypt and decrypt keys are kept")

	os.Args = os.Args[1:] // remove parent command
	flag.Parse()
	if helpFlag {
		flag.Usage()
		return
	}
	fmt.Printf("both-kept is %v\n", bothKept)
	fmt.Printf("serverName is %v\n", serverName)

	if err := genNewCertFiles(isEnclaveMode, bothKept); err != nil {
		panic(err)
	}
}

func genNewCertFiles(isEnclaveMode, bothKept bool) error {
	httpsPrivateKey, err := genAndSealPrivKey(isEnclaveMode, bothKept)
	if err != nil {
		return err
	}

	err = genSelfSignedCert(httpsPrivateKey)
	if err != nil {
		return err
	}

	err = genCSR(httpsPrivateKey)
	if err != nil {
		return err
	}

	return nil
}

func genAndSealPrivKey(isEnclaveMode, bothKept bool) (*rsa.PrivateKey, error) {
	if isEnclaveMode {
		if _, err := os.Stat(EncryptedHttpsKeyFile); err == nil {
			println("https key file already exists")
			return nil, errors.New("https key file already exists")
		}
	} else {
		if _, err := os.Stat(DecryptedHttpsKeyFile); err == nil {
			println("https key file already exists")
			return nil, errors.New("https key file already exists")
		}
	}

	priv, err := rsa.GenerateKey(&types.RandReader{}, 2048)
	if err != nil {
		println("failed to generate https private key")
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		println("failed to marshal private key")
		return nil, err
	}

	var needWriteEncryptedKey bool
	var needWriteDecryptedKey bool
	if bothKept {
		needWriteEncryptedKey = true
		needWriteDecryptedKey = true
	} else {
		needWriteEncryptedKey = isEnclaveMode
		needWriteDecryptedKey = !isEnclaveMode
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	if needWriteEncryptedKey {
		privSealed, err := ecrypto.SealWithUniqueKey(privPEM, nil)
		if err != nil {
			println("failed to seal private key")
			return nil, err
		}

		err = os.WriteFile(EncryptedHttpsKeyFile, privSealed, 0600)
		if err != nil {
			println("failed to write encrypted private key")
			return nil, err
		}
	}

	if needWriteDecryptedKey {
		err = os.WriteFile(DecryptedHttpsKeyFile, privPEM, 0600)
		if err != nil {
			println("failed to write decrypted private key")
			return nil, err
		}
	}

	return priv, nil
}

func genSelfSignedCert(httpsPrivateKey *rsa.PrivateKey) error {
	template := x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: serverName},
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		DNSNames:     []string{serverName},
	}

	derBytes, err := x509.CreateCertificate(&types.RandReader{}, &template, &template, &httpsPrivateKey.PublicKey, httpsPrivateKey)
	if err != nil {
		println("failed to create certificate")
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err = os.WriteFile(HttpsCertFile, certPEM, 0644)
	if err != nil {
		println("failed to write certificate")
		return err
	}

	return nil
}

// https://gist.github.com/svicknesh/85a369e7852f615ecfc07983a9b736af
// https://gist.github.com/gambol99/d55afd69217b8e2dd727be99f0a20e7d
// https://stackoverflow.com/questions/26043321/create-a-certificate-signing-request-csr-with-an-email-address-in-go
func genCSR(httpsPrivateKey *rsa.PrivateKey) error {
	csrData, err := loadCsrData()
	if err != nil {
		return err
	}

	oidEmailAddress := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	subj := pkix.Name{
		CommonName:         csrData.CommonName,
		Country:            []string{csrData.Country},
		Province:           []string{csrData.Province},
		Locality:           []string{csrData.Locality},
		Organization:       []string{csrData.Organization},
		OrganizationalUnit: []string{csrData.OrganizationalUnit},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: csrData.EmailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{csrData.EmailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(&types.RandReader{}, &template, httpsPrivateKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	err = os.WriteFile(CsrFile, csrPEM, 0644)
	if err != nil {
		println("failed to write csr")
		return err
	}

	return nil
}

func loadCsrData() (*CSRData, error) {
	csrDataBytes, err := os.ReadFile(csrDataFile)
	if err != nil {
		return nil, err
	}

	var csrData CSRData
	err = json.Unmarshal(csrDataBytes, &csrData)
	return &csrData, err
}

func LoadCertAndDecryptedKey(certFile, decryptedKeyFile string) (tls.Certificate, error) {
	return loadCert(certFile, decryptedKeyFile, false)
}

func LoadCertAndEncryptedKey(certFile, encryptedKeyFile string) (tls.Certificate, error) {
	return loadCert(certFile, encryptedKeyFile, true)
}

func loadCert(certFile, httpsKeyFile string, isEnclaveMode bool) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEMBlock, err := os.ReadFile(httpsKeyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	if isEnclaveMode {
		keyPEMBlock, err = ecrypto.Unseal(keyPEMBlock, nil)
		if err != nil {
			return tls.Certificate{}, err
		}
	}

	return tls.X509KeyPair(certPEMBlock, keyPEMBlock)
}
