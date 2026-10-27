package keepassxc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestEncryptedStatusRoundTrip(t *testing.T) {
	s, err := newCryptoSession()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.accept(message{PublicKey: base64.StdEncoding.EncodeToString(pub[:]), Success: "true"}); err != nil {
		t.Fatal(err)
	}
	request, n, err := s.request(true)
	if err != nil {
		t.Fatal(err)
	}
	if request.TriggerUnlock != "true" {
		t.Fatal("missing unlock flag")
	}
	ciphertext, _ := base64.StdEncoding.DecodeString(request.Message)
	plain, ok := box.Open(nil, ciphertext, &n, s.public, priv)
	if !ok || string(plain) != `{"action":"get-databasehash"}` {
		t.Fatal("request is not valid NaCl browser protocol")
	}
	for i := range n {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	data, _ := json.Marshal(map[string]string{"success": "true", "hash": "test-database"})
	response := message{Nonce: base64.StdEncoding.EncodeToString(n[:]), Message: base64.StdEncoding.EncodeToString(box.Seal(nil, data, &n, s.public, priv))}
	_, original, err := s.request(false)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the request nonce (inverse little-endian increment).
	for i := range n {
		before := n[i]
		n[i]--
		if before != 0 {
			break
		}
	}
	if opened, err := s.isOpen(response, n); err != nil || !opened {
		t.Fatalf("opened=%v err=%v", opened, err)
	}
	if _, err := s.isOpen(response, original); err == nil {
		t.Fatal("accepted replayed response")
	}
	if opened, err := s.isOpen(message{ErrorCode: "1"}, n); err != nil || opened {
		t.Fatalf("locked status=%v err=%v", opened, err)
	}
	response.Message = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := s.isOpen(response, n); err == nil {
		t.Fatal("accepted unauthenticated response")
	}
}

func TestNativeMessages(t *testing.T) {
	var stream bytes.Buffer
	for _, action := range []string{"get-databasehash", "database-unlocked"} {
		if err := writeMessage(&stream, message{Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{"get-databasehash", "database-unlocked"} {
		got, err := readMessage(&stream)
		if err != nil || got.Action != action {
			t.Fatalf("message=%v err=%v", got, err)
		}
	}
	for _, data := range [][]byte{{0, 0, 0, 0}, {255, 255, 255, 255}, {3, 0, 0, 0, '{'}} {
		if _, err := readMessage(bytes.NewReader(data)); err == nil {
			t.Fatal("accepted invalid/truncated message")
		}
	}
}
