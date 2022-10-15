package protocol

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

type RecipientInfo interface {
	decryptKey(keyPair tls.Certificate) (key []byte, err error)
	MarshalASN1RawValue() (asn1.RawValue, error)
}

func ParseRecipientInfo(value asn1.RawValue) (RecipientInfo, error) {
	var ktri KeyTransRecipientInfo
	err := unmarshalFully(value.FullBytes, &ktri)
	if err == nil {
		if ktri.Version == 0 && ktri.Rid.IAS.SerialNumber != nil && ktri.Rid.SKI == nil {
			return &ktri, nil
		} else if ktri.Version == 2 && ktri.Rid.IAS.SerialNumber == nil && ktri.Rid.SKI != nil {
			return &ktri, nil
		}
	}

	var kari KeyAgreeRecipientInfo
	err = unmarshalFully(value.FullBytes, &kari)
	if err == nil && kari.Version == 3 {
		return &kari, nil
	}

	var kekri KEKRecipientInfo
	err = unmarshalFully(value.FullBytes, &kekri)
	if err == nil && kekri.Version == 4 {
		return &kekri, nil
	}

	var pwri PasswordRecipientInfo
	err = unmarshalFully(value.FullBytes, &pwri)
	if err == nil && pwri.Version == 0 {
		return &pwri, nil
	}

	var ori OtherRecipientInfo
	err = unmarshalFully(value.FullBytes, &ori)
	if err == nil {
		return &ori, nil
	}

	return nil, fmt.Errorf("cant parse recipient info")
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
