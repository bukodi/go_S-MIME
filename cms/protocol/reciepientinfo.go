package protocol

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
)

type RecipientInfo interface {
	decryptKey(keyPair tls.Certificate) (key []byte, err error)
	MarshalASN1RawValue() (asn1.RawValue, error)
}

func ParseRecipientInfo(value asn1.RawValue) (RecipientInfo, error) {

	if value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence {
		var ktri KeyTransRecipientInfo
		if err := unmarshalFully(value.FullBytes, &ktri); err != nil {
			return nil, err
		}
		return &ktri, nil
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 1 {
		var kari KeyAgreeRecipientInfo
		if err := unmarshalFullyWithParams(value.FullBytes, &kari, "tag:1"); err != nil {
			return nil, err
		}
		return &kari, nil
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 2 {
		var kekri KEKRecipientInfo
		if err := unmarshalFullyWithParams(value.FullBytes, &kekri, "tag:2"); err != nil {
			return nil, err
		}
		return &kekri, nil
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 3 {
		var pwri PasswordRecipientInfo
		if err := unmarshalFullyWithParams(value.FullBytes, &pwri, "tag:3"); err != nil {
			return nil, err
		}
		return &pwri, nil
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 4 {
		var ori OtherRecipientInfo
		if err := unmarshalFullyWithParams(value.FullBytes, &ori, "tag:2"); err != nil {
			return nil, err
		}
		return &ori, nil
	}

	return nil, fmt.Errorf("cant parse recipient info: \n%s\n", base64.StdEncoding.EncodeToString(value.FullBytes))
}

// NewRecipientInfo creates RecipientInfo for giben recipient and key.
func NewRecipientInfo(recipient *x509.Certificate, key []byte) (RecipientInfo, error) {

	switch recipient.PublicKeyAlgorithm {
	case x509.RSA:
		ktri, err := encryptKeyRSA(key, recipient)
		if err != nil {
			return nil, err
		}
		return &ktri, nil
	case x509.ECDSA:
		kari, err := encryptKeyECDH(key, recipient)
		if err != nil {
			return nil, err
		}
		return &kari, nil
	default:
		return nil, errors.New("Public key algorithm not supported")
	}
}
