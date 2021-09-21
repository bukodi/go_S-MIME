package protocol

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/bukodi/go_S-MIME/oid"
)

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
type SignerInfo struct {
	Version            int                      ``                          // CMSVersion ::= INTEGER    { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
	SID                asn1.RawValue            ``                          //
	DigestAlgorithm    pkix.AlgorithmIdentifier ``                          // DigestAlgorithmIdentifier ::= AlgorithmIdentifier
	SignedAttrs        []Attribute              `asn1:"set,optional,tag:0"` // SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
	SignatureAlgorithm pkix.AlgorithmIdentifier ``                          // SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
	Signature          []byte                   ``                          // SignatureValue ::= OCTET STRING
	UnsignedAttrs      []Attribute              `asn1:"set,optional,tag:1"` // UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
}

//SignerIdentifier ::= CHOICE {
//	issuerAndSerialNumber IssuerAndSerialNumber,
//	subjectKeyIdentifier [0] ExtensionSubjectKeyIdentifier }
type SignerIdentifier struct {
	IAS IssuerAndSerialNumber `asn1:"optional"`
	SKI []byte                `asn1:"optional,tag:0"`
}

func (sid SignerIdentifier) ToASN1RawValue() (*asn1.RawValue, error) {
	var asn1Bytes []byte
	var err error
	if sid.IAS.Issuer.Bytes != nil && sid.SKI == nil {
		asn1Bytes, err = asn1.Marshal(sid.IAS)
		if err != nil {
			return nil, err
		}
	} else if sid.IAS.Issuer.Bytes == nil && sid.SKI != nil {
		asn1Bytes, err = asn1.Marshal(sid.SKI)
		if err != nil {
			return nil, err
		}
	}
	var asn1RawValue asn1.RawValue
	rest, err := asn1.Unmarshal(asn1Bytes, &asn1RawValue)
	if err != nil {
		return nil, err
	}
	if rest != nil && len(rest) > 0 {
		return nil, fmt.Errorf("unprocessed bytes: %v", rest)
	}
	return &asn1RawValue, nil
}

// version is the syntax version number.  If the SignerIdentifier is
// the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
// the SignerIdentifier is subjectKeyIdentifier, then the version
// MUST be 3.
func (si SignerInfo) SignedIdentifier() (*SignerIdentifier, error) {
	sid := SignerIdentifier{}
	if si.Version == 1 {
		sid.IAS = IssuerAndSerialNumber{}
		rest, err := asn1.Unmarshal(si.SID.FullBytes, &sid.IAS)
		if err != nil {
			return nil, err
		}
		if rest != nil && len(rest) > 0 {
			return nil, fmt.Errorf("unprocessed bytes: %v", rest)
		}
	} else if si.Version == 3 {
		sid.SKI = make([]byte, 0)
		rest, err := asn1.Unmarshal(si.SID.FullBytes, sid.SKI)
		if err != nil {
			return nil, err
		}
		if rest != nil && len(rest) > 0 {
			return nil, fmt.Errorf("unprocessed bytes: %v", rest)
		}
	} else {
		return nil, fmt.Errorf("unsupported version value: %d", si.Version)
	}
	return &sid, nil
}

// FindCertificate finds this SignerInfo's certificate in a slice of
// certificates.
func (si SignerInfo) FindCertificate(certs []*x509.Certificate) (*x509.Certificate, error) {
	sid, err := si.SignedIdentifier()
	if err != nil {
		return nil, err
	}
	switch si.Version {
	case 1: // SID is issuer and serial number
		isn := sid.IAS

		for _, cert := range certs {
			if bytes.Equal(cert.RawIssuer, isn.Issuer.FullBytes) && isn.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return cert, nil
			}
		}
	case 3: // SID is ExtensionSubjectKeyIdentifier
		ski := sid.SKI

		for _, cert := range certs {
			for _, ext := range cert.Extensions {
				if oid.ExtensionSubjectKeyIdentifier.Equal(ext.Id) {
					if bytes.Equal(ski, ext.Value) {
						return cert, nil
					}
				}
			}
		}
	default:
		return nil, ErrUnsupported
	}

	return nil, ErrNoCertificate
}

// Hash gets the crypto.Hash associated with this SignerInfo's DigestAlgorithm.
// 0 is returned for unrecognized algorithms.
func (si SignerInfo) Hash() (crypto.Hash, error) {
	algo := si.DigestAlgorithm.Algorithm.String()
	hash := oid.DigestAlgorithmToCryptoHash[algo]
	if hash == 0 || !hash.Available() {
		return 0, ErrUnsupported
	}

	return hash, nil
}

// X509SignatureAlgorithm gets the x509.SignatureAlgorithm that should be used
// for verifying this SignerInfo's signature.
func (si SignerInfo) X509SignatureAlgorithm() x509.SignatureAlgorithm {
	var (
		sigOID    = si.SignatureAlgorithm.Algorithm.String()
		digestOID = si.DigestAlgorithm.Algorithm.String()
	)

	if sa := oid.SignatureAlgorithmToX509SignatureAlgorithm[sigOID]; sa != x509.UnknownSignatureAlgorithm {
		return sa
	}

	return oid.PublicKeyAndDigestAlgorithmToX509SignatureAlgorithm[sigOID][digestOID]

}

// GetContentTypeAttribute gets the signed ContentType attribute from the
// SignerInfo.
func (si SignerInfo) GetContentTypeAttribute() (asn1.ObjectIdentifier, error) {
	var sa Attributes
	sa = si.SignedAttrs
	rv, err := sa.GetOnlyAttributeValueBytes(oid.AttributeContentType)
	if err != nil {
		return nil, err
	}

	var ct asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(rv.FullBytes, &ct); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return ct, nil
}

// GetMessageDigestAttribute gets the signed MessageDigest attribute from the
// SignerInfo.
func (si SignerInfo) GetMessageDigestAttribute() ([]byte, error) {
	var sa Attributes
	sa = si.SignedAttrs
	rv, err := sa.GetOnlyAttributeValueBytes(oid.AttributeMessageDigest)
	if err != nil {
		return nil, err
	}
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagOctetString {
		return nil, ASN1Error{"bad class or tag"}
	}

	return rv.Bytes, nil
}

// GetSigningTimeAttribute gets the signed SigningTime attribute from the
// SignerInfo.
func (si SignerInfo) GetSigningTimeAttribute() (time.Time, error) {
	var t time.Time

	var sa Attributes
	sa = si.SignedAttrs
	rv, err := sa.GetOnlyAttributeValueBytes(oid.AttributeSigningTime)
	if err != nil {
		return t, err
	}
	if rv.Class != asn1.ClassUniversal || (rv.Tag != asn1.TagUTCTime && rv.Tag != asn1.TagGeneralizedTime) {
		return t, ASN1Error{"bad class or tag"}
	}

	if rest, err := asn1.Unmarshal(rv.FullBytes, &t); err != nil {
		return t, err
	} else if len(rest) > 0 {
		return t, ErrTrailingData
	}

	return t, nil
}
