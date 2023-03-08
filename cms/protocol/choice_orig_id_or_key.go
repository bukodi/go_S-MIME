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
	// TODO: handle EXPLICIT tag:0
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
	// Process the EXPLICIT tag header
	if value.Class != asn1.ClassContextSpecific || value.Tag != 0 {
		return fmt.Errorf("OriginatorIdentifierOrKey: unexpected tag %d\nFull ASN.1 as base64: %s", value.Tag, base64.StdEncoding.EncodeToString(value.FullBytes))
	}
	var innerValue asn1.RawValue
	if err := unmarshalFullyWithParams(value.Bytes, &innerValue, ""); err != nil {
		return err
	}

	// Process the inner OriginatorIdentifierOrKey
	if innerValue.Class == asn1.ClassUniversal && innerValue.Tag == asn1.TagSequence {
		oriId.IAS = new(IssuerAndSerialNumber)
		if err := unmarshalFully(innerValue.FullBytes, oriId.IAS); err != nil {
			return err
		} else {
			return nil
		}
	}

	if innerValue.Class == asn1.ClassContextSpecific && innerValue.Tag == 0 {
		oriId.SKI = make([]byte, 0)
		if err := unmarshalFullyWithParams(innerValue.FullBytes, &(oriId.SKI), "tag:0"); err != nil {
			return err
		} else {
			return nil
		}
	}

	if innerValue.Class == asn1.ClassContextSpecific && innerValue.Tag == 1 {
		oriId.OriginatorKey = new(OriginatorPublicKey)
		if err := unmarshalFullyWithParams(innerValue.FullBytes, oriId.OriginatorKey, "tag:1"); err != nil {
			return err
		} else {
			return nil
		}
	}

	return fmt.Errorf("cant parse recipient OriginatorIdentifierOrKey: \n%s\n", base64.StdEncoding.EncodeToString(value.FullBytes))
}
