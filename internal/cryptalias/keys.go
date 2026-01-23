package cryptalias

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

type PublicKey ed25519.PublicKey

func (k PublicKey) MarshalYAML() (interface{}, error) {
	if len(k) == 0 {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

func (k *PublicKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	decoded, err := decodeKeyFromYAML(unmarshal)
	if err != nil {
		return err
	}
	*k = PublicKey(decoded)
	return nil
}

type PrivateKey ed25519.PrivateKey

func (k PrivateKey) MarshalYAML() (interface{}, error) {
	if len(k) == 0 {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

func (k *PrivateKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	decoded, err := decodeKeyFromYAML(unmarshal)
	if err != nil {
		return err
	}
	*k = PrivateKey(decoded)
	return nil
}

func decodeKeyFromYAML(unmarshal func(interface{}) error) ([]byte, error) {
	var raw interface{}
	if err := unmarshal(&raw); err != nil {
		return nil, err
	}
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		if v == "" {
			return nil, nil
		}
		return base64.StdEncoding.DecodeString(v)
	case []byte:
		if len(v) == 0 {
			return nil, nil
		}
		return v, nil
	case []interface{}:
		if len(v) == 0 {
			return nil, nil
		}
		out := make([]byte, len(v))
		for i, n := range v {
			num, ok := n.(int)
			if !ok {
				return nil, fmt.Errorf("invalid key byte at index %d", i)
			}
			if num < 0 || num > 255 {
				return nil, fmt.Errorf("invalid key byte at index %d", i)
			}
			out[i] = byte(num)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported key format %T", raw)
	}
}
