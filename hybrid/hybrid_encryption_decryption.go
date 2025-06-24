package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

const publicKey = "./keys/public.pem"
const privateKey = "./keys/private.pem"

func Encrypt(toEncrypt any) ([]byte, error) {
	// Generate a random AES key
	aesKey := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}

	// Encrypt the data with AES
	plaintext, err := json.Marshal(toEncrypt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Encrypt the AES key with RSA
	publicKeyPEM, err := os.ReadFile(publicKey)
	if err != nil {
		return nil, err
	}
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), aesKey)
	if err != nil {
		return nil, err
	}

	// Combine the encrypted key and encrypted data
	result := struct {
		Key  []byte `json:"key"`
		Data []byte `json:"data"`
	}{
		Key:  encryptedKey,
		Data: ciphertext,
	}

	return json.Marshal(result)
}

func Decrypt(encryptedData []byte) ([]byte, error) {
	// Parse the encrypted data structure
	var data struct {
		Key  []byte `json:"key"`
		Data []byte `json:"data"`
	}
	if err := json.Unmarshal(encryptedData, &data); err != nil {
		return nil, err
	}

	// Decrypt the AES key with RSA
	privateKeyPEM, err := os.ReadFile(privateKey)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, data.Key)
	if err != nil {
		return nil, err
	}

	// Decrypt the data with AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data.Data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data.Data[:nonceSize], data.Data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
