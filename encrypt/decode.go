package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/elliotchance/phpserialize"
)

func decodeBase64(text string) []byte {
	rawDecodedText, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return rawDecodedText
}

func decode(key, ciphertext string) (string, error) {
	key = "base64:" + key

	decodeBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("ciphertext value must in base64 format")
	}
	var payload struct {
		IV    string
		Value string
		Mac   string
	}
	err = json.Unmarshal(decodeBytes, &payload)
	if err != nil {
		return "", errors.New("ciphertext value must be valid")
	}
	encryptedText, err := base64.StdEncoding.DecodeString(payload.Value)
	if err != nil {
		return "", errors.New("encrypted text must be valid base64 format")
	}
	iv, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil {
		return "", errors.New("iv in payload must be valid base64 format")
	}
	var keyBytes []byte
	if strings.HasPrefix(key, "base64:") {
		keyBytes, err = base64.StdEncoding.DecodeString(string(key[7:]))
		if err != nil {
			return "", errors.New("seems like you provide a key in base64 format, but it's not valid")
		}
	} else {
		keyBytes = []byte(key)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedText, encryptedText)
	var cleartext string
	err = phpserialize.Unmarshal(encryptedText, &cleartext)
	if err != nil {
		return "", err
	}
	return cleartext, nil
}

func pad(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, errors.New("pkcs7: block size must be between 1 and 255 inclusive")
	}

	padLen := blockSize - len(src)%blockSize
	padding := []byte{byte(padLen)}
	padding = bytes.Repeat(padding, padLen)

	return append(src, padding...), nil
}
