package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
		Headers: map[string]string{
			"Author":       "Abhishek Kumar Rabidas",
			"Generated-On": time.Now().Format(time.RFC3339),
		},
	})
	err = os.WriteFile("./keys/private.pem", privateKeyPEM, 0644)
	if err != nil {
		panic(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
		Headers: map[string]string{
			"Author":       "Abhishek Kumar Rabidas",
			"Generated-On": time.Now().Format(time.RFC3339),
		},
	})
	err = os.WriteFile("./keys/public.pem", publicKeyPEM, 0644)
	if err != nil {
		panic(err)
	}
	log.Println("Public and private keys generated successfully.")
}
