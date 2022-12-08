# Notes
Golang compile with no window
```
GOOS=windows GOARCH=amd64 go build  -ldflags -H=windowsgui -o file.exe file.go
```
Obfuscate build
```
GOOS=windows GOARCH=amd64 ~/go/bin/garble build  -ldflags="-w -s -H=windowsgui" -o file.exe file.go
```

# Anew (python3)

Compares old file to new file, if new file contains lines that dont exist in the old file it will print them to screen for piping into other tools.

# Nessus Merge (python3)

Combines two nessus files into one.

# Hostscan (bash)

Basic scanner for all hosts, can be used as `hostscan.sh 192.168.1.1 "--top-ports 100" "--top-ports 20"` to define the nmap ports you want to scan

# Fileupload, server and client (go)
Small golang script that will allow file uploads to the current dir over https using a baked in key. Client is formatted to perform the upload for you or you can use curl:
```
curl -sk -X POST -H "X-API-Key: Pentest12345" -F "file=@test.txt" -F "filename=test.txt" https://127.0.0.1:8443/files
```

# Multi Downloader (go)
Will try and download an exe from a remote webserver using 4 methods, if any method is successful it will run the file and exit the program, if one fails it will move to the last and finally use certutil (which flags defender) as a last attempt.

# Encode / Decode (go)
## Encode
Encodes a file with xor to file.txt. 
## Decode
Decodes a file.txt with xor to file.exe then runs

# Cname Scanner (go)
Checks  a list of domains from stdin, checks the cname, if the cname does not contain the domain name it prints the domain and the cname.
```
cat domains.txt | go run cnamescanner.go
```

# Get HTTP Response (go)
Script that takes a list of urls from stdin, requests the url and writes the response to a file called responses.txt in the format url,base64encoded(response.body) which is useful for monitoring sites or taking a snapshot of the responses for future tests.
