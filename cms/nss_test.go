package cms

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"testing"
)

////go:embed testdata/csabiGenerated.p7m
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
	var recipient tls.Certificate
	if _, err := x509.ParseCertificate(eccCert); err != nil {
		panic(err)
	} else {
		recipient.Certificate = [][]byte{eccCert}
	}

	if pk, err := x509.ParsePKCS8PrivateKey(eccPrivKey); err != nil {
		panic(err)
	} else {
		recipient.PrivateKey = pk
	}
	return &recipient
}

func Test(t *testing.T) {
	cms, err := New(*eccRecipient, *rsaRecipient)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cms.Decrypt(testMsg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s\n", plain)

}
