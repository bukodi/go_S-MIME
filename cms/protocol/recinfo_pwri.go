package protocol

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var _ RecipientInfo = &PasswordRecipientInfo{}

// PasswordRecipientInfo ::= SEQUENCE {
// version CMSVersion,   -- Always set to 0
// keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
// keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
// encryptedKey EncryptedKey }
type PasswordRecipientInfo struct {
	Version                int
	KeyDerivationAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

func (pwRI *PasswordRecipientInfo) MarshalASN1RawValue() (asn1.RawValue, error) {
	asn1Bytes, err := asn1.Marshal(*pwRI)
	if err != nil {
		return asn1.RawValue{}, err
	}
	var asn1RawValue asn1.RawValue
	err = unmarshalFully(asn1Bytes, &asn1RawValue)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1RawValue, nil
}

func (pwRI *PasswordRecipientInfo) decryptKey(keyPair tls.Certificate) (key []byte, err error) {
	panic("Implement me!")
}
