package main

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	inputFilename := os.Args[1]
	input, err := ioutil.ReadFile(inputFilename)
	if err != nil {
		log.Fatal(err)
	}

	key := []byte("mysecretkey")
	encoded := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		encoded[i] = input[i] ^ key[i%len(key)]
	}

	encodedString := base64.StdEncoding.EncodeToString(encoded)

	err = ioutil.WriteFile(os.Args[1] + ".txt", []byte(encodedString), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
