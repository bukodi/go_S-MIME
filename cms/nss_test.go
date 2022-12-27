package cms

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"os"
	"testing"
)

// //go:embed testdata/csabiGenerated.p7m
//
//go:embed testdata/opensslGenerated.p7m
var testMsg []byte

//go:embed testdata/eccRecipient.pkcs8
var eccPrivKey []byte

//go:embed testdata/eccRecipient.cer
var eccCert []byte

var eccRecipient *tls.Certificate
var rsaRecipient *tls.Certificate

func init() {
	eccRecipient = readRecipient("testdata/eccRecipient.pkcs8", "testdata/eccRecipient.cer")
	rsaRecipient = readRecipient("testdata/rsaRecipient.pkcs8", "testdata/rsaRecipient.cer")
}

func readRecipient(pkcs8Path string, certPath string) *tls.Certificate {
	keyBytes, err := os.ReadFile(pkcs8Path)
	if err != nil {
		panic(err)
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	var recipient tls.Certificate
	if _, err := x509.ParseCertificate(certBytes); err != nil {
		panic(err)
	} else {
		recipient.Certificate = [][]byte{certBytes}
	}

	if pk, err := x509.ParsePKCS8PrivateKey(keyBytes); err != nil {
		panic(err)
	} else {
		recipient.PrivateKey = pk
	}
	return &recipient
}

func TestKARI(t *testing.T) {
	cms, err := New(*eccRecipient)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cms.Decrypt(testMsg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s\n", plain)
}

func TestKTRI(t *testing.T) {
	cms, err := New(*rsaRecipient)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cms.Decrypt(testMsg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s\n", plain)
}
