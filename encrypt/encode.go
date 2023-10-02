package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/elliotchance/phpserialize"
)

func encode(chave, ciphertext string) (string, error) {
	key := decodeBase64(chave)
	ciphertextNew, err := phpserialize.Marshal(ciphertext, nil)
	if err != nil {
		return "", err
	}
	plaintext := []byte(ciphertextNew)

	plaintext, err = pad(plaintext, aes.BlockSize)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(plaintext, plaintext)

	payload := make(map[string]string)
	payload["iv"] = base64.StdEncoding.EncodeToString(iv)
	payload["value"] = base64.StdEncoding.EncodeToString(plaintext)

	h := hmac.New(sha256.New, []byte(key))
	io.WriteString(h, payload["iv"]+payload["value"])
	payload["mac"] = fmt.Sprintf("%x", h.Sum(nil))

	data, err := json.Marshal(payload)

	if err != nil {
		return "", err
	}
	ciphertext = base64.StdEncoding.EncodeToString(data)
	return ciphertext, nil
}
