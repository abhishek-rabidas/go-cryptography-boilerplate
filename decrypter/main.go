package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"log"
)

const PRIVATE_KEY_FILE = "./keys/private.pem"

func main() {
	privateKeyPEM, err := ioutil.ReadFile(PRIVATE_KEY_FILE)
	if err != nil {
		panic(err)
	}
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	encryptedHex := "4579dc3aeee445821875a5232160da5294d7e3f918e3b013ad8fa5bf7dacf0addf58fd4691690a5eebe132a366a9e9b62483f2ab278339e4f72045e58d8e1bede0eafe732d88f7e4a3853c82eaf6d055ebb017186e8c17aaf6538ce389c2bf840d7be3959f9bb4498514296d0a473306824b1ddeab48ee3c0962568ba6a14eb3c10a320018e41ade96a3911e6c0f91329f8be9d493b7d4edecaeb494bb09b7610998dd1211935b51a95e210f216143cb4aa9c807408cf601eb522583c61d4c26bc67e4fd941248a6aac094c2d4d0a4ef35061422d8d0c18526ccd8da626b596c2b22694221119ef547a74399aa920188368a486cfb2eab395a0230f6e3a511dc"
	ciphertext, err := hex.DecodeString(encryptedHex)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		panic(err.Error())
	}

	log.Printf("Decrypted: [%s]\n", plaintext)
}
