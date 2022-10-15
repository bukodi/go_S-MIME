package protocol

import (
	"crypto/tls"
	"encoding/asn1"
)

var _ RecipientInfo = &OtherRecipientInfo{}

//OtherRecipientInfo ::= SEQUENCE {
//oriType OBJECT IDENTIFIER,
//oriValue ANY DEFINED BY oriType }
type OtherRecipientInfo struct {
	OriType  asn1.ObjectIdentifier
	OriValue asn1.RawValue
}

func (oRI *OtherRecipientInfo) MarshalASN1RawValue() (asn1.RawValue, error) {
	asn1Bytes, err := asn1.Marshal(*oRI)
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

func (oRI *OtherRecipientInfo) decryptKey(keyPair tls.Certificate) (key []byte, err error) {
	panic("Implement me!")
}
