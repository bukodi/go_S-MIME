package protocol

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/bukodi/go_S-MIME/oid"
	"log"
)

//KeyTransRecipientInfo ::= SEQUENCE {
//	version CMSVersion,  -- always set to 0 or 2
//	rid RecipientIdentifier,
//	keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//	encryptedKey EncryptedKey }
var _ RecipientInfo = &KeyTransRecipientInfo{}

type KeyTransRecipientInfo struct {
	Version                int
	Rid                    RecipientIdentifier `asn1:"choice"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

func (ktri *KeyTransRecipientInfo) MarshalASN1RawValue() (asn1.RawValue, error) {
	asn1Bytes, err := asn1.Marshal(*ktri)
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

func (ktri *KeyTransRecipientInfo) decryptKey(keyPair tls.Certificate) (key []byte, err error) {

	ias, err := NewIssuerAndSerialNumber(keyPair.Leaf)
	if err != nil {
		return
	}

	ski := keyPair.Leaf.SubjectKeyId

	certPubAlg := oid.DelPublicKeyAlgorithmToEncrytionAlgorithm[keyPair.Leaf.PublicKeyAlgorithm]
	var decOpts crypto.DecrypterOpts
	pkcs15CertwithOAEP := false

	if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(oid.PublicKeyAlgorithmRSAESOAEP) {

		if certPubAlg.Equal(oid.PublicKeyAlgorithmRSA) {
			pkcs15CertwithOAEP = true
		}

		decOpts, err = parseRSAESOAEPparams(ktri.KeyEncryptionAlgorithm.Parameters.FullBytes)
		if err != nil {
			return
		}
	}

	//version is the syntax version number.  If the SignerIdentifier is
	//the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
	//the SignerIdentifier is subjectKeyIdentifier, then the version
	//MUST be 3.
	switch ktri.Version {
	case 0:
		if ias.Equal(ktri.Rid.IAS) {
			if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(certPubAlg) || pkcs15CertwithOAEP {

				decrypter := keyPair.PrivateKey.(crypto.Decrypter)
				return decrypter.Decrypt(rand.Reader, ktri.EncryptedKey, decOpts)

			}
			log.Println("Key encrytion algorithm not matching")
		}
	case 2:
		if bytes.Equal(ski, ktri.Rid.SKI) {
			if ktri.KeyEncryptionAlgorithm.Algorithm.Equal(certPubAlg) || pkcs15CertwithOAEP {

				decrypter := keyPair.PrivateKey.(crypto.Decrypter)
				return decrypter.Decrypt(rand.Reader, ktri.EncryptedKey, decOpts)

			}
			log.Println("Key encrytion algorithm not matching")
		}
	default:
		return nil, ErrUnsupported
	}

	return nil, nil
}

//RecipientIdentifier ::= CHOICE {
//	issuerAndSerialNumber IssuerAndSerialNumber,
//	subjectKeyIdentifier [0] ExtensionSubjectKeyIdentifier }
type RecipientIdentifier struct {
	IAS IssuerAndSerialNumber `asn1:"optional"`
	SKI []byte                `asn1:"optional,tag:0"`
}

func encryptKeyRSA(key []byte, recipient *x509.Certificate) (ktri KeyTransRecipientInfo, err error) {
	ktri.Version = 0 //issuerAndSerialNumber

	switch ktri.Version {
	case 0:
		ias, err := NewIssuerAndSerialNumber(recipient)
		if err != nil {
			log.Fatal(err)
		}
		ktri.Rid.IAS = ias
	case 2:
		ktri.Rid.SKI = recipient.SubjectKeyId
	}

	if pub := recipient.PublicKey.(*rsa.PublicKey); pub != nil {

		if isRSAPSS(recipient) {
			hash := crypto.SHA256
			var oaepparam RSAESOAEPparams
			oaepparam, err = newRSAESOAEPparams(hash)
			if err != nil {
				return
			}
			var oaepparamRV asn1.RawValue
			oaepparamRV, err = asn1RawValue(oaepparam)
			if err != nil {
				return
			}
			ktri.KeyEncryptionAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oid.PublicKeyAlgorithmRSAESOAEP, Parameters: oaepparamRV}
			h := hash.New()
			ktri.EncryptedKey, err = rsa.EncryptOAEP(h, rand.Reader, pub, key, nil)
			return
		}

		ktri.KeyEncryptionAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oid.PublicKeyAlgorithmRSA}
		ktri.EncryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, pub, key)
		return
	}

	err = ErrUnsupportedAlgorithm
	return
}
