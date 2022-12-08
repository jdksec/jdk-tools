package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

const numWorkers = 100 // number of worker threads

func main() {
	// create a wait group to wait for all workers to finish
	var wg sync.WaitGroup

	// create a channel to receive domains from the main thread
	domainChan := make(chan string)

	// create the worker threads
	for i := 0; i < numWorkers; i++ {
		// increment the wait group counter
		wg.Add(1)

		// start a new worker goroutine
		go func(id int) {
			// decrement the wait group counter when the goroutine finishes
			defer wg.Done()

			// loop until the domain channel is closed
			for domain := range domainChan {
				// lookup the cname for the domain
				cname, err := net.LookupCNAME(domain)
				if err != nil {
					continue
				}

				// check if the cname does not contain the domain
				if !strings.Contains(cname, domain) {
					// print the domain and the cname
					fmt.Printf("[cname-discovered] %s [%s]\n", domain, cname)
				}
			}
		}(i) // pass the worker id to the goroutine
	}

	// create a scanner to read from standard input
	scanner := bufio.NewScanner(os.Stdin)

	// loop through each line from standard input
	for scanner.Scan() {
		// get the domain from the line
		domain := scanner.Text()

		// send the domain to the worker threads via the channel
		domainChan <- domain
	}

	// close the domain channel to signal the worker threads to stop
	close(domainChan)

	// wait for all worker threads to finish
	wg.Wait()
}
