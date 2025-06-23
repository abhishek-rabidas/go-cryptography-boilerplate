package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
)

const PUBLIC_KEY_FILE = "./keys/public.pem"

func main() {
	publicKeyPEM, err := ioutil.ReadFile(PUBLIC_KEY_FILE)
	if err != nil {
		panic(err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	obj := Example{
		Id:   1,
		Name: "John Doe",
		Age:  30,
	}

	plaintext, err := json.Marshal(obj)
	if err != nil {
		panic("Encoding error for body")
	}
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), plaintext)
	if err != nil {
		panic(err)
	}

	log.Printf("Encrypted: [%x]\n\n", ciphertext)
}

type Example struct {
	Id   uint   `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}
