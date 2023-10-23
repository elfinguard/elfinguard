package certs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	keyFile  = "./key/key.pem"
	certFile = "./key/cert.pem"
	csrFile  = "./key/csr.pem"
)

func removeTestFiles() {
	_ = os.RemoveAll(keyFile)
	_ = os.RemoveAll(certFile)
	_ = os.RemoveAll(csrFile)
}

func TestGenCertFiles(t *testing.T) {
	csrDataFile = "csr_data_eg.json"
	removeTestFiles()
	defer removeTestFiles()

	err := genNewCertFiles(false, true)
	require.NoError(t, err)
	_, err = loadCert(keyFile, certFile, false)
	require.NoError(t, err)
}
