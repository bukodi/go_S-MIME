package protocol

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

//	RecipientIdentifier ::= CHOICE {
//		issuerAndSerialNumber IssuerAndSerialNumber,
//		subjectKeyIdentifier [0] ExtensionSubjectKeyIdentifier }
type RecipientIdentifier struct {
	IAS *IssuerAndSerialNumber
	SKI []byte
}

func (rId *RecipientIdentifier) Marshal() (asn1.RawValue, error) {
	if rId != nil {
		return rId.IAS.RawValue()
	} else if len(rId.SKI) > 0 {
		return asn1RawValue(rId.SKI, "tag:0")
	} else {
		return asn1.RawValue{}, fmt.Errorf("both chioces of RecipientIdentifier are empty")
	}
}

func (rId *RecipientIdentifier) Unmarshal(value asn1.RawValue) error {
	if value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence {
		rId.IAS = new(IssuerAndSerialNumber)
		if err := unmarshalFully(value.FullBytes, rId.IAS); err != nil {
			return err
		} else {
			return nil
		}
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 0 {
		rId.SKI = make([]byte, 0)
		if err := unmarshalFullyWithParams(value.FullBytes, rId.SKI, "tag:0"); err != nil {
			return err
		} else {
			return nil
		}
	}

	return fmt.Errorf("cant parse recipient identifier: \n%s\n", base64.StdEncoding.EncodeToString(value.FullBytes))
}
