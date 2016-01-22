package main

import (
	"fmt"
	"os"

        "github.com/coreos/go-tspi/tpmclient"
//        "github.com/coreos/go-tspi/verification"
)

func main() {
	tpm := tpmclient.New(os.Args[1])

	aikpub, aikblob, err := tpm.GenerateAIK()
	if err != nil {
		fmt.Printf("Unable to generate AIK: %s\n", err)
	}

	quote, _, err := tpm.GetQuote(aikpub, aikblob, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	if err != nil {
		fmt.Printf("Unable to get quote: %s\n", err)
	}

	fmt.Printf("Quote: %s\n", quote);
}
