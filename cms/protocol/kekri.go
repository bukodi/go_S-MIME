package protocol

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

//KEKIdentifier ::= SEQUENCE {
//keyIdentifier OCTET STRING,
//date GeneralizedTime OPTIONAL,
//other OtherKeyAttribute OPTIONAL }
type KEKIdentifier struct {
	KeyIdentifier []byte
	Date          time.Time         `asn1:"optional"`
	Other         OtherKeyAttribute `asn1:"optional"`
}

//KEKRecipientInfo ::= SEQUENCE {
//version CMSVersion,  -- always set to 4
//kekid KEKIdentifier,
//keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//encryptedKey EncryptedKey }
type KEKRecipientInfo struct {
	Version                int
	KEKId                  KEKIdentifier
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

var _ RecipientInfo = &KEKRecipientInfo{}

func (kekRI *KEKRecipientInfo) MarshalASN1RawValue() (asn1.RawValue, error) {
	asn1Bytes, err := asn1.Marshal(*kekRI)
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

func (kekRI *KEKRecipientInfo) decryptKey(keyPair tls.Certificate) (key []byte, err error) {
	panic("not implemented")
}
