package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
)

func main() {
	// Create a buffered reader to read URLs from stdin
	reader := bufio.NewReader(os.Stdin)

	// Use a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Create a map to store the base64 encoded responses
	responses := make(map[string]string)

	// Read URLs from stdin until there are no more
	for {
		url, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		// Trim the whitespace from the URL and add it to the WaitGroup
		url = strings.TrimSpace(url)
		wg.Add(1)

		// Launch a goroutine to request the URL and base64 encode the response
		go func() {
			// Request the URL
			resp, err := http.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Read the response body
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return
			}

			// Encode the response body and headers as base64
			var buf bytes.Buffer
			encoder := base64.NewEncoder(base64.StdEncoding, &buf)
			encoder.Write(body)
			encoder.Close()
			encodedResponse := buf.String()

			// Add the encoded response to the map
			responses[url] = encodedResponse

			// Decrement the WaitGroup counter
			wg.Done()
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Open the responses file for writing
	f, err := os.Create("responses.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Write the encoded responses to the file
	for url, encodedResponse := range responses {
		f.WriteString(url + "," + encodedResponse + "\n")
	}
}
