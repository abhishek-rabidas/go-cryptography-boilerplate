package main

import (
	"encoding/json"
	"log"
)

func main() {
	obj := Example{
		Id:   1,
		Name: "John Doe",
		Age:  30,
	}

	log.Printf("Original object: %+v\n\n", obj)

	encrypted, err := Encrypt(obj)
	if err != nil {
		panic(err)
	}

	log.Printf("Encrypted object: %s\n\n", encrypted)

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		panic(err)
	}
	var decryptedObj Example
	if err := json.Unmarshal(decrypted, &decryptedObj); err != nil {
		panic(err)
	}
	log.Printf("Decrypted object: %+v", decryptedObj)
}

type Example struct {
	Id   uint   `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}
