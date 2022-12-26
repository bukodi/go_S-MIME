package protocol

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
)

//	OriginatorIdentifierOrKey ::= CHOICE {
//		issuerAndSerialNumber IssuerAndSerialNumber,
//		subjectKeyIdentifier [0] ExtensionSubjectKeyIdentifier,
//		originatorKey [1] OriginatorPublicKey }
type OriginatorIdentifierOrKey struct {
	IAS           *IssuerAndSerialNumber
	SKI           []byte
	OriginatorKey *OriginatorPublicKey
}

func (oriId *OriginatorIdentifierOrKey) Marshal() (asn1.RawValue, error) {
	if oriId.IAS != nil {
		return oriId.IAS.RawValue()
	} else if len(oriId.SKI) > 0 {
		return asn1RawValue(oriId.SKI, "tag:0")
	} else if oriId.OriginatorKey != nil {
		return asn1RawValue(oriId.OriginatorKey, "tag:1")
	} else {
		return asn1.RawValue{}, fmt.Errorf("all chioces of OriginatorIdentifierOrKey are empty")
	}
}

func (oriId *OriginatorIdentifierOrKey) Unmarshal(value asn1.RawValue) error {
	if value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence {
		oriId.IAS = new(IssuerAndSerialNumber)
		if err := unmarshalFully(value.FullBytes, oriId.IAS); err != nil {
			return err
		} else {
			return nil
		}
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 0 {
		oriId.SKI = make([]byte, 0)
		if err := unmarshalFullyWithParams(value.FullBytes, oriId.SKI, "tag:0"); err != nil {
			return err
		} else {
			return nil
		}
	}

	if value.Class == asn1.ClassContextSpecific && value.Tag == 1 {
		oriId.OriginatorKey = new(OriginatorPublicKey)
		if err := unmarshalFullyWithParams(value.FullBytes, oriId.OriginatorKey, "tag:1"); err != nil {
			return err
		} else {
			return nil
		}
	}

	return fmt.Errorf("cant parse recipient OriginatorIdentifierOrKey: \n%s\n", base64.StdEncoding.EncodeToString(value.FullBytes))
}
