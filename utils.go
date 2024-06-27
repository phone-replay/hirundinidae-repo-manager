package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func PadKey(key string) string {
	for len(key) < 32 {
		key += "0"
	}
	return key[:32]
}

func encrypt(data []byte, passphrase string) (string, error) {
	key := []byte(PadKey(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func GenerateEncrypt() {
	passphrase := os.Getenv("DECRYPTION_PASSPHRASE") // Change this to your passphrase

	fileData, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		panic(err)
	}

	encryptedData, err := encrypt(fileData, passphrase)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("credentials.json.enc", []byte(encryptedData), 0644)
	if err != nil {
		panic(err)
	}

	fmt.Println("File encrypted successfully!")
}
