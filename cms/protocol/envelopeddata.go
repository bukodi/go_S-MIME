package protocol

import (
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"

	asn "github.com/bukodi/go_S-MIME/asn1"
	"github.com/bukodi/go_S-MIME/oid"
)

const dummy = asn.TagBitString

//EnvelopedData ::= SEQUENCE {
//	version CMSVersion,
//	originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//	RawRecipientInfos RawRecipientInfos,
//	encryptedContentInfo EncryptedContentInfo,
//	unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
type EnvelopedData struct {
	Version           int
	OriginatorInfo    asn1.RawValue        `asn1:"optional,tag:0"`
	RawRecipientInfos []asn1.RawValue      `asn1:"set,choice"`
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
	recInfos := make([]RecipientInfo, 0)
	for _, asn1Ri := range ed.RawRecipientInfos {
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(asn1Ri.FullBytes))
		ri, err := ParseRecipientInfo(asn1Ri)
		if err == nil {
			recInfos = append(recInfos, ri)
		}
	}
	return recInfos
}

func (ed *EnvelopedData) decryptKey(keyPair tls.Certificate) ([]byte, error) {

	for _, asn1Ri := range ed.RawRecipientInfos {
		ri, err := ParseRecipientInfo(asn1Ri)
		if err == nil {
			key, err := ri.decryptKey(keyPair)
			if err == nil {
				return key, nil
			}
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

	der, err := asn.Marshal(ed)
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
