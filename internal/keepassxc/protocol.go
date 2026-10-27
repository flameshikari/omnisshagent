package keepassxc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const maxMessage = 1024 * 1024

type message struct {
	Action        string `json:"action"`
	ClientID      string `json:"clientID,omitempty"`
	PublicKey     string `json:"publicKey,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	Message       string `json:"message,omitempty"`
	TriggerUnlock string `json:"triggerUnlock,omitempty"`
	Success       string `json:"success,omitempty"`
	ErrorCode     string `json:"errorCode,omitempty"`
}

func readMessage(r io.Reader) (message, error) {
	var size uint32
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return message{}, err
	}
	if size == 0 || size > maxMessage {
		return message{}, errors.New("invalid native message size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return message{}, err
	}
	var m message
	if err := json.Unmarshal(data, &m); err != nil {
		return message{}, errors.New("invalid native message")
	}
	return m, nil
}

func writeMessage(w io.Writer, m message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(data))); err != nil {
		return err
	}
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

type cryptoSession struct {
	public, private, peer *[32]byte
	clientID              string
}

func newCryptoSession() (*cryptoSession, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &cryptoSession{public: pub, private: priv, clientID: base64.RawURLEncoding.EncodeToString(id)}, nil
}

func nonce() ([24]byte, error) {
	var n [24]byte
	_, err := rand.Read(n[:])
	return n, err
}

func (s *cryptoSession) handshake() (message, error) {
	n, err := nonce()
	return message{Action: "change-public-keys", ClientID: s.clientID, PublicKey: base64.StdEncoding.EncodeToString(s.public[:]), Nonce: base64.StdEncoding.EncodeToString(n[:])}, err
}

func (s *cryptoSession) accept(m message) error {
	key, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil || len(key) != 32 || m.Success != "true" {
		return errors.New("KeePassXC key exchange failed")
	}
	s.peer = new([32]byte)
	copy(s.peer[:], key)
	return nil
}

func (s *cryptoSession) request(unlock bool) (message, [24]byte, error) {
	n, err := nonce()
	if err != nil {
		return message{}, n, err
	}
	ciphertext := box.Seal(nil, []byte(`{"action":"get-databasehash"}`), &n, s.peer, s.private)
	m := message{Action: "get-databasehash", ClientID: s.clientID, Nonce: base64.StdEncoding.EncodeToString(n[:]), Message: base64.StdEncoding.EncodeToString(ciphertext)}
	if unlock {
		m.TriggerUnlock = "true"
	}
	return m, n, nil
}

func (s *cryptoSession) isOpen(m message, requestNonce [24]byte) (bool, error) {
	if m.ErrorCode == "1" {
		return false, nil
	}
	if m.ErrorCode != "" {
		return false, errors.New("KeePassXC rejected status request")
	}
	// KeePassXC increments the request nonce as a little-endian integer.
	for i := range requestNonce {
		requestNonce[i]++
		if requestNonce[i] != 0 {
			break
		}
	}
	n, err := base64.StdEncoding.DecodeString(m.Nonce)
	if err != nil || string(n) != string(requestNonce[:]) {
		return false, errors.New("invalid KeePassXC response nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(m.Message)
	if err != nil {
		return false, errors.New("invalid KeePassXC ciphertext")
	}
	plain, ok := box.Open(nil, ciphertext, &requestNonce, s.peer, s.private)
	if !ok {
		return false, errors.New("invalid KeePassXC response authentication")
	}
	var response struct {
		Success string `json:"success"`
		Hash    string `json:"hash"`
	}
	if json.Unmarshal(plain, &response) != nil || response.Success != "true" || response.Hash == "" {
		return false, errors.New("invalid KeePassXC database status")
	}
	return true, nil
}
