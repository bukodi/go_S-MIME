package protocol

import (
	"crypto/tls"
	"encoding/asn1"
	"log"

	"github.com/bukodi/go_S-MIME/oid"
)

//AuthEnvelopedData ::= SEQUENCE {
//	version CMSVersion,
//	originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//	RawRecipientInfos RecipientInfos,
//	authEncryptedContentInfo EncryptedContentInfo,
///	authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
//	mac MessageAuthenticationCode,
//	unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
//https://tools.ietf.org/html/rfc5083##section-2.1
type AuthEnvelopedData struct {
	Version           int
	OriginatorInfo    asn1.RawValue   `asn1:"optional,tag:0"`
	RawRecipientInfos []asn1.RawValue `asn1:"set,choice"`
	AECI              EncryptedContentInfo
	AauthAttrs        []Attribute `asn1:"set,optional,tag:1"`
	MAC               []byte
	UnAauthAttrs      []Attribute `asn1:"set,optional,tag:2"`
}

// Decrypt decrypts AuthEnvelopedData and returns the plaintext.
func (ed *AuthEnvelopedData) Decrypt(keyPair []tls.Certificate) (plain []byte, err error) {

	// Find the right key
	var key []byte
	for i := range keyPair {
		key, err = ed.decryptKey(keyPair[i])
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
		ContentEncryptionAlgorithmIdentifier: ed.AECI.ContentEncryptionAlgorithm,
	}
	encAlg.MAC = ed.MAC

	plain, err = encAlg.Decrypt(ed.AECI.EContent)

	return
}

func (ed *AuthEnvelopedData) RecipientInfos() []RecipientInfo {
	recInfos := make([]RecipientInfo, 0)
	for _, asn1Ri := range ed.RawRecipientInfos {
		ri, err := ParseRecipientInfo(asn1Ri)
		if err == nil {
			recInfos = append(recInfos, ri)
		} else {
			// TODO: log error gracefully
		}
	}
	return recInfos
}

func (ed *AuthEnvelopedData) decryptKey(keyPair tls.Certificate) ([]byte, error) {
	for _, ri := range ed.RecipientInfos() {
		key, err := ri.decryptKey(keyPair)
		if err == nil {
			return key, nil
		}
	}
	return nil, ErrNoKeyFound
}

// NewAuthEnvelopedData creates AuthEnvelopedData from an EncryptedContentInfo with mac and given RawRecipientInfos.
func NewAuthEnvelopedData(eci *EncryptedContentInfo, reciInfos []RecipientInfo, mac []byte) (AuthEnvelopedData, error) {
	version := 0

	ed := AuthEnvelopedData{
		Version:           version,
		RawRecipientInfos: make([]asn1.RawValue, 0),
		AECI:              *eci,
		MAC:               mac,
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

func authcontentInfo(ed AuthEnvelopedData) (ci ContentInfo, err error) {

	der, err := asn1.Marshal(ed)
	if err != nil {
		return
	}

	ci = ContentInfo{
		ContentType: oid.ContentTypeAuthEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      der,
			IsCompound: true,
		},
	}

	return
}

// ContentInfo marshals AuthEnvelopedData and returns ContentInfo.
func (ed AuthEnvelopedData) ContentInfo() (ContentInfo, error) {
	nilCI := *new(ContentInfo)

	der, err := asn1.Marshal(ed)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		return nilCI, err
	}

	return ContentInfo{
		ContentType: oid.ContentTypeAuthEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      der,
			IsCompound: true,
		},
	}, nil

}

// AuthEnvelopedDataContent unmarshals ContentInfo and returns AuthEnvelopedData if
// content type is AuthEnvelopedData.
func (ci ContentInfo) AuthEnvelopedDataContent() (*AuthEnvelopedData, error) {
	if !ci.ContentType.Equal(oid.ContentTypeAuthEnvelopedData) {
		return nil, ErrWrongType
	}

	ed := new(AuthEnvelopedData)
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, ed); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return ed, nil
}
