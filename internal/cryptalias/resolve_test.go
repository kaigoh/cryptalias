package cryptalias

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type testData struct {
	JWS     string `json:"jws"`
	JWK     jwkKey `json:"jwk"`
	Payload struct {
		Address string `json:"address"`
	} `json:"payload"`
}

func loadTestData(t *testing.T) testData {
	t.Helper()
	path := filepath.Join("..", "..", "clients", "testdata", "jws.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test data: %v", err)
	}
	var td testData
	if err := json.Unmarshal(data, &td); err != nil {
		t.Fatalf("unmarshal test data: %v", err)
	}
	return td
}

func TestDecodeJWSPayload(t *testing.T) {
	td := loadTestData(t)
	payload, err := decodeJWSPayload(td.JWS)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Address != td.Payload.Address {
		t.Fatalf("address mismatch: got %q want %q", payload.Address, td.Payload.Address)
	}
}

func TestVerifyJWS(t *testing.T) {
	td := loadTestData(t)
	payload, err := verifyJwsAndDecodePayload(td.JWS, td.JWK)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if payload.Address != td.Payload.Address {
		t.Fatalf("address mismatch: got %q want %q", payload.Address, td.Payload.Address)
	}
}
