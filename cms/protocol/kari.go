package protocol

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

//KeyAgreeRecipientInfo ::= SEQUENCE {
//	version CMSVersion,  -- always set to 3
//	originator [0] EXPLICIT OriginatorIdentifierOrKey,
//	ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//	keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//	recipientEncryptedKeys RecipientEncryptedKeys }
var _ RecipientInfo = &KeyAgreeRecipientInfo{}

type KeyAgreeRecipientInfo struct {
	Version                int
	Originator             OriginatorIdentifierOrKey `asn1:"explicit,choice,tag:0"`
	UKM                    []byte                    `asn1:"explicit,optional,tag:1"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier  ``
	RecipientEncryptedKeys []RecipientEncryptedKey   `asn1:"sequence"` //RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
}

func (kari *KeyAgreeRecipientInfo) MarshalASN1RawValue() (asn1.RawValue, error) {
	asn1Bytes, err := asn1.Marshal(*kari)
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

// ErrUnsupportedAlgorithm is returned if the algorithm is unsupported.
var ErrUnsupportedAlgorithm = errors.New("cms: cannot decrypt data: unsupported algorithm")

//OriginatorIdentifierOrKey ::= CHOICE {
//	issuerAndSerialNumber IssuerAndSerialNumber,
//	subjectKeyIdentifier [0] ExtensionSubjectKeyIdentifier,
//	originatorKey [1] OriginatorPublicKey }
type OriginatorIdentifierOrKey struct {
	IAS           IssuerAndSerialNumber `asn1:"optional"`
	SKI           []byte                `asn1:"optional,tag:0"`
	OriginatorKey OriginatorPublicKey   `asn1:"optional,tag:1"`
}

//OriginatorPublicKey ::= SEQUENCE {
//	algorithm AlgorithmIdentifier,
//	publicKey BIT STRING
type OriginatorPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

//RecipientEncryptedKey ::= SEQUENCE {
//	rid KeyAgreeRecipientIdentifier,
//	encryptedKey EncryptedKey }
type RecipientEncryptedKey struct {
	RID          KeyAgreeRecipientIdentifier `asn1:"choice"`
	EncryptedKey []byte
}

//KeyAgreeRecipientIdentifier ::= CHOICE {
//	issuerAndSerialNumber IssuerAndSerialNumber,
//	rKeyId [0] IMPLICIT RecipientKeyIdentifier }
type KeyAgreeRecipientIdentifier struct {
	IAS    IssuerAndSerialNumber  `asn1:"optional"`
	RKeyID RecipientKeyIdentifier `asn1:"optional,tag:0"`
}

//RecipientKeyIdentifier ::= SEQUENCE {
//	subjectKeyIdentifier SubjectKeyIdentifier,
//	date GeneralizedTime OPTIONAL,
//	other OtherKeyAttribute OPTIONAL }
type RecipientKeyIdentifier struct {
	SubjectKeyIdentifier []byte            //SubjectKeyIdentifier ::= OCTET STRING
	Date                 time.Time         `asn1:"optional"`
	Other                OtherKeyAttribute `asn1:"optional"`
}

//OtherKeyAttribute ::= SEQUENCE {
//	keyAttrId OBJECT IDENTIFIER,
//	keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
type OtherKeyAttribute struct {
	KeyAttrID asn1.ObjectIdentifier
	KeyAttr   asn1.RawValue `asn1:"optional"`
}
