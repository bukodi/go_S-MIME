package protocol

import (
	"encoding/asn1"
	"fmt"
	"strings"

	asn "github.com/bukodi/go_S-MIME/asn1"
)

func unmarshalFully(b []byte, val interface{}) (err error) {
	rest, err := asn1.Unmarshal(b, val)
	if err != nil {
		return err
	}
	if rest != nil && len(rest) > 0 {
		return fmt.Errorf("unprocessed bytes: %v", rest)
	}
	return nil
}

// RawValue marshals val and returns the asn1.RawValue
func asn1RawValue(val interface{}, params ...string) (asn1.RawValue, error) {
	param := strings.Join(params, ",")

	var rv asn1.RawValue
	var der []byte
	var err error
	if der, err = asn.MarshalWithParams(val, param); err != nil {
		return rv, err
	}

	if _, err = asn.Unmarshal(der, &rv); err != nil {
		return rv, err
	}
	return rv, err
}
