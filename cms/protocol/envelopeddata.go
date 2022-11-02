package protocol

import (
	"crypto/tls"
	"encoding/asn1"
	"fmt"
	"log"

	"github.com/bukodi/go_S-MIME/oid"
)

//EnvelopedData ::= SEQUENCE {
//	version CMSVersion,
//	originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//	RawRecipientInfos RawRecipientInfos,
//	encryptedContentInfo EncryptedContentInfo,
//	unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
type EnvelopedData struct {
	Version           int
	OriginatorInfo    asn1.RawValue        `asn1:"optional,tag:0"`
	RawRecipientInfos []asn1.RawValue      `asn1:"set"`
	ECI               EncryptedContentInfo ``
	UnprotectedAttrs  []Attribute          `asn1:"set,optional,tag:1"`
}

// Decrypt decrypts the EnvelopedData with the given keyPair and retuns the plaintext.
func (ed *EnvelopedData) Decrypt(keyPairs []tls.Certificate) (plain []byte, err error) {

	// Find the right key
	var key []byte
	for i := range keyPairs {
		key, err = ed.decryptKey(keyPairs[i])
		switch err {
		case ErrNoKeyFound:
			continue
		case nil:
			break
		default:
			return
		}
	}
	if key == nil {
		return nil, ErrNoKeyFound
	}

	encAlg := &oid.EncryptionAlgorithm{
		Key:                                  key,
		ContentEncryptionAlgorithmIdentifier: ed.ECI.ContentEncryptionAlgorithm,
	}

	plain, err = encAlg.Decrypt(ed.ECI.EContent)

	return
}
func (ed *EnvelopedData) RecipientInfos() []RecipientInfo {
	parsedRecipientInfos := make([]RecipientInfo, 0)
	for _, asn1Ri := range ed.RawRecipientInfos {
		ri, err := ParseRecipientInfo(asn1Ri)
		if err == nil {
			parsedRecipientInfos = append(parsedRecipientInfos, ri)
		} else {
			// log error gracefully
			fmt.Printf("%+v", err)
		}
	}
	return parsedRecipientInfos
}

func (ed *EnvelopedData) decryptKey(keyPair tls.Certificate) ([]byte, error) {
	for _, ri := range ed.RecipientInfos() {
		key, err := ri.decryptKey(keyPair)
		if err == nil {
			return key, nil
		}
	}
	return nil, ErrNoKeyFound
}

// EnvelopedDataContent returns EnvelopedData if ContentType is EnvelopedData.
func (ci ContentInfo) EnvelopedDataContent() (*EnvelopedData, error) {
	if !ci.ContentType.Equal(oid.ContentTypeEnvelopedData) {
		return nil, ErrWrongType
	}

	//var Ed interface{}
	ed := new(EnvelopedData)
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, ed); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return ed, nil
}

// ContentInfo returns new ContentInfo with ContentType EnvelopedData.
func (ed EnvelopedData) ContentInfo() (ContentInfo, error) {
	nilCI := *new(ContentInfo)

	der, err := asn1.Marshal(ed)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		return nilCI, err
	}

	return ContentInfo{
		ContentType: oid.ContentTypeEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      der,
			IsCompound: true,
		},
	}, nil

}

// NewEnvelopedData creates a new EnvelopedData from the given data.
func NewEnvelopedData(eci *EncryptedContentInfo, reciInfos []RecipientInfo) (EnvelopedData, error) {
	version := 0

	ed := EnvelopedData{
		Version:           version,
		RawRecipientInfos: make([]asn1.RawValue, 0),
		ECI:               *eci,
	}
	for _, recInfo := range reciInfos {
		asn1RecInfo, err := recInfo.MarshalASN1RawValue()
		if err != nil {
			return ed, err
		}
		ed.RawRecipientInfos = append(ed.RawRecipientInfos, asn1RecInfo)
	}

	return ed, nil
}
