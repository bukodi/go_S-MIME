package protocol

import (
	"encoding/asn1"
	"fmt"
	"strings"
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

func unmarshalFullyWithParams(b []byte, val interface{}, params string) (err error) {
	rest, err := asn1.UnmarshalWithParams(b, val, params)
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
	if der, err = asn1.MarshalWithParams(val, param); err != nil {
		return rv, err
	}

	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return rv, err
	}
	return rv, err
}
