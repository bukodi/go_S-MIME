package protocol

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

//	KeyAgreeRecipientIdentifier ::= CHOICE {
//		issuerAndSerialNumber IssuerAndSerialNumber,
//		rKeyId [0] IMPLICIT RecipientKeyIdentifier }
type KeyAgreeRecipientIdentifier struct {
	IAS    *IssuerAndSerialNumber  `asn1:"optional"`
	RKeyID *RecipientKeyIdentifier `asn1:"optional,tag:0"`
}

func (rId *KeyAgreeRecipientIdentifier) Marshal() (asn1.RawValue, error) {
	if rId != nil {
		return rId.IAS.RawValue()
	} else if rId.RKeyID != nil {
		return asn1RawValue(rId.RKeyID, "tag:0")
	} else {
		return asn1.RawValue{}, fmt.Errorf("both chioces of KeyAgreeRecipientIdentifier are empty")
	}
}

func (rId *KeyAgreeRecipientIdentifier) Unmarshal(value asn1.RawValue) error {
	if value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence {
		rId.IAS = new(IssuerAndSerialNumber)
		if err := unmarshalFully(value.FullBytes, rId.IAS); err != nil {
			return err
		} else {
			return nil
		}
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 0 {
		rId.RKeyID = new(RecipientKeyIdentifier)
		if err := unmarshalFullyWithParams(value.FullBytes, rId.RKeyID, "tag:0"); err != nil {
			return err
		} else {
			return nil
		}
	}

	return fmt.Errorf("cant parse KeyAgreeRecipientIdentifier: \n%s\n", base64.StdEncoding.EncodeToString(value.FullBytes))
}
