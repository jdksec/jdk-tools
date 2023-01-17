package main

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	// Read the input file
	inputFilename := os.Args[1]
	input, err := ioutil.ReadFile(inputFilename)
	if err != nil {
		log.Fatal(err)
	}

	// XOR-encode the input file using the secret key "mysecretkey"
	key := []byte("mysecretkey")
	encoded := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		encoded[i] = input[i] ^ key[i%len(key)]
	}

	// Encode the encoded file as a base64 value
	encodedString := base64.StdEncoding.EncodeToString(encoded)

	// Write the encoded file as a text file
	err = ioutil.WriteFile(os.Args[1] + ".txt", []byte(encodedString), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
