package protocol

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"github.com/bukodi/go_S-MIME/oid"
	"testing"
)

func TestMarshalUnmarshalKTRI(t *testing.T) {
	ktri := KeyTransRecipientInfo{
		Version: 0,
		Rid:     RecipientIdentifier{},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid.PublicKeyAlgorithmRSAESOAEP,
		},
		EncryptedKey: []byte{0x01, 0x02},
	}
	bytes, err := asn1.Marshal(ktri)
	if err != nil {
		t.Fatal(err)
	}
	var ktri2 KeyTransRecipientInfo
	err = unmarshalFully(bytes, &ktri2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%+v\n%+v\n", ktri, ktri2)
	t.Logf("\n%s\n", base64.StdEncoding.EncodeToString(bytes))
}
