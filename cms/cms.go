// Package cms contains high level functions for cryptographic message syntax RFC 5652.
package cms

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/bukodi/go_S-MIME/cms/protocol"
	"github.com/bukodi/go_S-MIME/oid"
	"github.com/bukodi/go_S-MIME/timestamp"
)

// CMS is an instance of cms to en-/decrypt and sign/verify CMS data
// with the given keyPairs and options.
type CMS struct {
	Intermediate, roots        *x509.CertPool
	Opts                       x509.VerifyOptions
	ContentEncryptionAlgorithm asn1.ObjectIdentifier
	TimeStampServer            string
	TimeStamp                  bool
	keyPairs                   []tls.Certificate
	signedAttrs                []protocol.Attribute
}

// New create a new instance of CMS with given keyPairs.
func New(cert ...tls.Certificate) (cms *CMS, err error) {
	root, err := x509.SystemCertPool()
	intermediate := x509.NewCertPool()
	cms = &CMS{
		Intermediate: intermediate,
		roots:        root,
		Opts: x509.VerifyOptions{
			Intermediates: intermediate,
			Roots:         root,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		ContentEncryptionAlgorithm: oid.EncryptionAlgorithmAES128CBC,
		TimeStampServer:            "http://timestamp.digicert.com",
		TimeStamp:                  false,
	}
	cms.keyPairs = cert

	for i := range cms.keyPairs {
		cms.keyPairs[i].Leaf, err = x509.ParseCertificate(cms.keyPairs[i].Certificate[0])
		if err != nil {
			return
		}
	}

	return
}

// AddAttribute adds an attribute to signedAttrs which will be used for signing
func (cms *CMS) AddAttribute(attrType asn1.ObjectIdentifier, val interface{}) (err error) {

	attr, err := protocol.NewAttribute(attrType, val)
	if err != nil {
		return
	}

	cms.signedAttrs = append(cms.signedAttrs, attr)

	return
}

// Encrypt encrypts data for the recipients and returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) Encrypt(data []byte, recipients []*x509.Certificate) (der []byte, err error) {

	eci, key, _, err := protocol.NewEncryptedContentInfo(oid.ContentTypeData, cms.ContentEncryptionAlgorithm, data)
	if err != nil {
		return
	}

	var reciInfos []protocol.RecipientInfo

	for _, recipient := range recipients {
		var rInfo protocol.RecipientInfo
		rInfo, err = protocol.NewRecipientInfo(recipient, key)
		if err != nil {
			return
		}
		reciInfos = append(reciInfos, rInfo)
	}

	ed, err := protocol.NewEnvelopedData(&eci, reciInfos)
	if err != nil {
		return
	}

	ci, err := ed.ContentInfo()
	if err != nil {
		return
	}

	return ci.DER()
}

// AuthEncrypt AEAD-encrypts data for the recipients and returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) AuthEncrypt(data []byte, recipients []*x509.Certificate) (der []byte, err error) {

	eci, key, mac, err := protocol.NewEncryptedContentInfo(oid.ContentTypeData, oid.EncryptionAlgorithmAES128GCM, data)
	if err != nil {
		return
	}

	var reciInfos []protocol.RecipientInfo

	for _, recipient := range recipients {
		var rInfo protocol.RecipientInfo
		rInfo, err = protocol.NewRecipientInfo(recipient, key)
		if err != nil {
			return
		}
		reciInfos = append(reciInfos, rInfo)
	}

	ed, err := protocol.NewAuthEnvelopedData(&eci, reciInfos, mac)
	if err != nil {
		return
	}

	ci, err := ed.ContentInfo()
	if err != nil {
		return
	}

	return ci.DER()
}

// AuthDecrypt AEAD-decrypts DER-encoded ASN.1 ContentInfo and returns plaintext.
func (cms *CMS) AuthDecrypt(contentInfo []byte) (plain []byte, err error) {
	contInf, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	ed, err := contInf.AuthEnvelopedDataContent()
	if err != nil {
		return
	}

	plain, err = ed.Decrypt(cms.keyPairs)

	return
}

// Decrypt decrypts DER-encoded ASN.1 ContentInfo and returns plaintext.
func (cms *CMS) Decrypt(contentInfo []byte) (plain []byte, err error) {
	contInf, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	ed, err := contInf.EnvelopedDataContent()
	if err != nil {
		return
	}

	fmt.Printf("--- Message recipients: \n")
	for _, ri := range ed.RecipientInfos() {
		if ktri, ok := ri.(*protocol.KeyTransRecipientInfo); ok {
			var rId protocol.RecipientIdentifier
			err = rId.Unmarshal(ktri.RawRid)
			if err != nil {
				return
			}
			if rId.IAS != nil {
				//rId.IAS.SerialNumber
				fmt.Printf("KTRI Serial = %s\n", rId.IAS.SerialNumber.String())
			} else if len(rId.SKI) > 0 {
				fmt.Printf("KTRI SKI = %s\n", hex.EncodeToString(rId.SKI))
			} else {
				err = fmt.Errorf("invalid case")
				return
			}
		} else if kari, ok := ri.(*protocol.KeyAgreeRecipientInfo); ok {
			for _, rEncKey := range kari.RecipientEncryptedKeys {
				var rId protocol.KeyAgreeRecipientIdentifier
				err = rId.Unmarshal(rEncKey.RawRID)
				if err != nil {
					return
				}
				if rId.IAS != nil {
					//rId.IAS.SerialNumber
					fmt.Printf("KARI Serial = %s\n", rId.IAS.SerialNumber.String())
				} else if rId.RKeyID != nil {
					fmt.Printf("KARI KeyId SKI = %s\n", hex.EncodeToString(rId.RKeyID.SubjectKeyIdentifier))
				} else {
					err = fmt.Errorf("invalid case")
					return
				}
			}
		} else {
			err = fmt.Errorf("invalid case")
			return
		}
	}
	fmt.Printf("--- Known keys: \n")
	for _, kp := range cms.keyPairs {
		leafCert, err2 := x509.ParseCertificate(kp.Certificate[0])
		if err2 != nil {
			return nil, err2
		}
		fmt.Printf("Cert Serial = %s\n", leafCert.SerialNumber.String())
	}
	plain, err = ed.Decrypt(cms.keyPairs)

	return
}

// Sign signs the data and returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) Sign(data []byte, detachedSignature ...bool) (der []byte, err error) {

	enci, err := protocol.NewDataEncapsulatedContentInfo(data)
	if err != nil {
		fmt.Println(err)
	}

	sd, err := protocol.NewSignedData(enci)
	if err != nil {
		fmt.Println(err)
	}

	for i := range cms.keyPairs {
		err = sd.AddSignerInfo(cms.keyPairs[i], cms.signedAttrs)
		if err != nil {
			return
		}
	}

	if cms.TimeStamp {
		err1 := AddTimestamps(sd, cms.TimeStampServer)
		if err1 != nil {
			log.Println(err1)
		}
	}

	if len(detachedSignature) > 0 && detachedSignature[0] {
		sd.EncapContentInfo.EContent = nil
	}

	ci, err := sd.ContentInfo()
	if err != nil {
		return
	}

	return ci.DER()
}

// Verify verifies the signature in contentInfo and returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) Verify(contentInfo []byte) (chains [][][]*x509.Certificate, err error) {
	ci, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return
	}

	chains, err = sd.Verify(cms.Opts, nil)

	return
}

// VerifyDetached verifies the detached signature of msg in contentInfo and returns DER-encoded ASN.1 ContentInfo.
func (cms *CMS) VerifyDetached(contentInfo, msg []byte) (chains [][][]*x509.Certificate, err error) {

	ci, err := protocol.ParseContentInfo(contentInfo)
	if err != nil {
		return
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return
	}

	chains, err = sd.Verify(cms.Opts, msg)

	return
}

// AddTimestamps adds a timestamp to the ContentTypeSignedData using the RFC3161
// timestamping service at the given URL. This timestamp proves that the signed
// message existed the time of generation, allowing verifiers to have more trust
// in old messages signed with revoked keys.
func AddTimestamps(sd *protocol.SignedData, url string) (err error) {
	var attrs = make([]protocol.Attribute, len(sd.SignerInfos))

	// Fetch all timestamp tokens before adding any to sd. This avoids a partial
	// failure.
	for i := range attrs {
		hash, err := sd.SignerInfos[i].Hash()
		if err != nil {
			return err
		}
		tsToken, err := timestamp.FetchTSToken(url, sd.SignerInfos[i].Signature, hash)
		if err != nil {
			return err
		}

		attr, err := protocol.NewAttribute(oid.AttributeTimeStampToken, tsToken)
		if err != nil {
			return err
		}

		attrs[i] = attr
	}

	for i := range attrs {
		sd.SignerInfos[i].UnsignedAttrs = append(sd.SignerInfos[i].UnsignedAttrs, attrs[i])
	}

	return nil
}
