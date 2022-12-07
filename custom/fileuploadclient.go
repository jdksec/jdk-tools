package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
)

func main() {
	// Get the file and URL from the command line arguments
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run fileuploadclient.go <file> <url>")
		os.Exit(1)
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	url := os.Args[2]

	// Create a new buffer to write the form data to
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	// Add the file to the form data
	fw, err := w.CreateFormFile("file", file.Name())
	if err != nil {
		panic(err)
	}
	if _, err = io.Copy(fw, file); err != nil {
		panic(err)
	}

	// Add the filename to the form data
	if fw, err = w.CreateFormField("filename"); err != nil {
		panic(err)
	}
	if _, err = fw.Write([]byte(file.Name())); err != nil {
		panic(err)
	}

	// Close the writer to ensure all data is written
	if err = w.Close(); err != nil {
		panic(err)
	}

	// Create a new HTTP client and POST request
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		panic(err)
	}

	// Set the content type of the request to the type of the form data
	req.Header.Set("Content-Type", w.FormDataContentType())
	// Set the X-API-Key header
	req.Header.Set("X-API-Key", "yourkey")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Print the response status
	fmt.Println("Response status:", resp.Status)
}
