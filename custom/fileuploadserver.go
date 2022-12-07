package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	// # Update the Key
	// openssl genrsa -out server.key 2048
	// openssl req -new -key server.key -out server.csr
	// openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
	// cat server.crt | base64 -w0
	// server.key | base64 -w0

	// Upload a file
	// curl -sk -X POST -H "X-API-Key: Pentest12345" -F "file=@test.txt" -F "filename=test.txt" https://127.0.0.1:8443/files, or use fileuploadclient.go

	server_crt_b64 := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURFVENDQWZrQ0ZHbWdtSjhJVHdycU8zUXo5ZEM5ejh4a2p3dFRNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1FVXgKQ3pBSkJnTlZCQVlUQWtGVk1STXdFUVlEVlFRSURBcFRiMjFsTFZOMFlYUmxNU0V3SHdZRFZRUUtEQmhKYm5SbApjbTVsZENCWGFXUm5hWFJ6SUZCMGVTQk1kR1F3SGhjTk1qSXhNakEzTVRNMU5qQXdXaGNOTWpNeE1qQTNNVE0xCk5qQXdXakJGTVFzd0NRWURWUVFHRXdKQlZURVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVoTUI4R0ExVUUKQ2d3WVNXNTBaWEp1WlhRZ1YybGtaMmwwY3lCUWRIa2dUSFJrTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQwpBUThBTUlJQkNnS0NBUUVBdDFZTFFkakxPSEZXbVZvYlBvd3hYTnNiaVRRQVRxUVBMVDFKUUMrL1l0ZTJ1ZThVCmk4OGhXVGgxdENqWDFrSlNQMEcrT2tXMFlUbWZnWkNaZ3BDeTR0ZnpNVjFaUjNINUkyQjY0MDhLNE9qK2VZenAKS0MzZTkzMVVlMGNwU3pRVGFidFRjT3cvVkdGcE9TYlJZejF3V044UjRxaG9pV1lKREQydmZGL01lSlcxQzQzRgpnUzFSSnVaVVFqeUdzREs1T2lXem13cFRzWUZGQ1Q5NUZsdDJXZzlHRWdGVHF4Vi8ySmFrY2JINk5aaXl6c0l1CnpHWnlNUUhNRUVldTRrWmVSOUI5amMzUXR3d3lTZ3JlOXljc1hqZm9zalNUNjVhMVdOekRGazNBN1dvTy9Hb1MKZ0pXMnJoeWFQVSt2VFkycmVjRlNtR1J4ZW5jbW05WVNTcFMvdlFJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQQpBNElCQVFBaTZJbkR4RGhQdi9RcGw5OWtRK0Q0ZXZKQThFRWF3ckNCY0dFTEo0V3hpUG1kWSt3UGdqWmlUYjJzCjg1cjloMHFyMG1WNG9KR0F3MktuQzBZTGE4aVpwdzBNTFFYaTdkMHZXbEl1SThBVHhYeUJhYVEyV3Y2WmVtdVEKY1RudVdHeDVrTW9JWFkzM3oxcG13MkJ5SzF0aWpGVzJVWGlWcTR0Q3loYWNRb0tScUI4MGp4enJ3a3JML2MwdgpRcUM0SlZnSTI1YVlUNDhsc0d3MHhmNllBaHJFTXpVQ080aHJPRmQ0UlJlTVBnejRqQXh4ekp6TURhSTNNQ1A5CmhvZjFwbFkyQkhYVDg0blE1MnNoTndUekY0MFBBNkdVYnpKOW1GSFoxb2lZWkwxSmR1SlhncVd3T3RhRE1zWUUKR1FLeUE1S1VRUGgxblJUSU1vU0d3Mk01QjRVSgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
	server_key_b64 := "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdDFZTFFkakxPSEZXbVZvYlBvd3hYTnNiaVRRQVRxUVBMVDFKUUMrL1l0ZTJ1ZThVCmk4OGhXVGgxdENqWDFrSlNQMEcrT2tXMFlUbWZnWkNaZ3BDeTR0ZnpNVjFaUjNINUkyQjY0MDhLNE9qK2VZenAKS0MzZTkzMVVlMGNwU3pRVGFidFRjT3cvVkdGcE9TYlJZejF3V044UjRxaG9pV1lKREQydmZGL01lSlcxQzQzRgpnUzFSSnVaVVFqeUdzREs1T2lXem13cFRzWUZGQ1Q5NUZsdDJXZzlHRWdGVHF4Vi8ySmFrY2JINk5aaXl6c0l1CnpHWnlNUUhNRUVldTRrWmVSOUI5amMzUXR3d3lTZ3JlOXljc1hqZm9zalNUNjVhMVdOekRGazNBN1dvTy9Hb1MKZ0pXMnJoeWFQVSt2VFkycmVjRlNtR1J4ZW5jbW05WVNTcFMvdlFJREFRQUJBb0lCQUE1YitlTzlaQ1ZXa3k3TgpwT2FnT2xtSWU3NmlTUWZmeDZTR2NVOUtyaFhDeVhnRXBycFFqYzhjSWZQcll3UlFDM3NTM2lCWVIwbDZKdWtSCjkwUUhxMHNqR05RYitKc2s3UnQ5T2dMRnRSZHFpRXZpNG53WUk2ZUV0SEkzWDUrWlE0LzdjUXllSkZPcWtZQTkKYnhienYvSGwvdE9lMXhrejJhK1F3VWJmaGZkSHVJQzVBN0hiRkFJdTVFWTBwQStkZVVWMlNsczJiYW5mYTE5Wgpsdy92N0JBU0xnSGR4V3FGUzFxb0dkak82Q05HYWRPR21EL0JWcitSeGJHUVRFeURTcVZxbkV2dmNlVEtnUU5ECjBNOVBYSlJKTkcyejVRSDJoQmxVZWFITE1UZUZtZ1lsUVdzY0JEelVTdjVDakRwdEtleVJhUDhtbXppTFpmc3UKVXJSSm9ZMENnWUVBNFhxb3d3YlFzK3d0UkxJQjl4Vy9tclJVVytLaVg2VHBTbDd2M3gxZmNzSzZSNEVXVko2VQoxUmpzV1JhNE91VUZwLzFtMmVMUERFamRPUnBXRDRuQ05aa2ExVmoxd2tkY2N6cnEwQmZIU0o4RXNsZ1FJOTlYCnZhSkd2UlNNSlI2bDZJRG1FNW80c3VENzZxdEJqb092WUhzRytITy85TVNVWEVnaGpMVVZDZThDZ1lFQTBDY0oKbUkyc2tXVjRKeGxJOWdmTG1hbk1YVWZ6emU1US8wUGZkeTgvVjlQZHZrYnF1NXNCV0xXZU15dmJodGxaZTd2dwpxZTNaNTI2NW9lZnVDZFc0QlBBVXJoMDNoY1Yvcloxc0tUL1NOSFdseVNKUlkxWlU2S2krRXR4Y0ttanZFR2EwCldFRTEveDd4ZzdSS2pOMk1lNjlRRi91cW1tQ3Iyb0hGNGlzYUxSTUNnWUJJMWNpQ0IwZVBkekZBU1lnYytxZUUKSDlCSVJqTlJWZ0lPQmhEU0w3alBaMXVwRVdmWE9jcTE4M0VWYmlOZzB1NDZ6NzVUajlKMkUydHlzTEV3SDczZQpkbkNXamtBRTIreGZSSjdwVFdVUWJsMmtCcEpnSkJ0QnBKUFpMRFFCSVo5U05hRWNuK3JFemF4U3A3TnJoOW8wCi9raklKUXZTMDFWaFllT0VnbElqZlFLQmdRREt1K3JkdWNkRlNkWVFCdEdJUjZsbS9mbDlOVEpoOVdiUWFQUUMKNm5MQWdTc3RRM2NteUY4MFhwZzU4Tko4OGI3MUErVHdMU2laLzc4djBXeUlDYStVcDUwTXhJb3FjV1RjM1VIVwpuMEdHTkx3SFBiU1ZreVZhQWRnM0dJZHdDd29sS0ZNb3prTGdPK3d4UWUyR2E5YUROUXBHZ2FqMWVZaUladk1zClNKelRId0tCZ0NaekN0TnVvemlWTHFsQ1dtY2hSRm1yTG1lNDcvb2U4U1QrNjBFUmE0Q3J3R2tmMUJFZzNmMFoKUDVuVGlUdzdRMlFlVWFuQWxROVN0dWQ4dHJFRmcwZFBiSmFsbHlOUjRTd2liNnNudzFhb2FoemdUcnQ5REF4SQpBZ0RNcjhoWXBTejBQWjFucEN1L0FjbWtDWEZJWDk0RTZNcUVCd0pIUng3Z0M2MWs1cU9WCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="

	// decode the private key
	serverCrt, err := base64.StdEncoding.DecodeString(server_crt_b64)
	if err != nil {
		panic(err)
	}
	serverKey, err := base64.StdEncoding.DecodeString(server_key_b64)
	if err != nil {
		panic(err)
	}

	// save the decoded keys to files
	err = ioutil.WriteFile("server.crt", serverCrt, 0644)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("server.key", serverKey, 0644)
	if err != nil {
		panic(err)
	}

	// Load the TLS certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		panic(err)
	}

	// Create a TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Listen on port 8443 using TLS
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/files", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check for the "X-API-Key" header
		if r.Header.Get("X-API-Key") != "Pentest12345" {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		// Parse the multipart/form-data request
		err := r.ParseMultipartForm(32 << 20) // maxMemory is 32MB
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Get the file from the request
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Get the file name from the request
		filename := r.FormValue("filename")
		fmt.Println(filename)

		// Check if the file name is valid
		if filename == "" {
			http.Error(w, "Missing file name", http.StatusBadRequest)
			return
		}

		// Write the file to the specified file name
		f, err := os.Create(filename)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		io.Copy(f, file)

		w.WriteHeader(http.StatusOK)
	})

	server.ListenAndServeTLS("", "")
}
