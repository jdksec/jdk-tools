# Anew

Compares old file to new file, if new file contains lines that dont exist in the old file it will print them to screen for piping into other tools.

# Nessus Merge

Combines two nessus files into one.

# Hostscan

Basic scanner for all hosts, can be used as `hostscan.sh 192.168.1.1 "--top-ports 100" "--top-ports 20"` to define the nmap ports you want to scan

# Fileupload (server and client)
Small golang script that will allow file uploads to the current dir over https using a baked in key. Client is formatted to perform the upload for you or you can use curl:
```
curl -sk -X POST -H "X-API-Key: Pentest12345" -F "file=@test.txt" -F "filename=test.txt" https://127.0.0.1:8443/files
```

# Multi Downloader
Will try and download an exe from a remote webserver using 4 methods, if any method is successful it will run the file and exit the program, if one fails it will move to the last and finally use certutil (which flags defender) as a last attempt.
