package main

import "fmt"
//import "attestation"
import "tpmclient"

func main() {
	tpm := tpmclient.New("10.7.3.112:12041")
//	ekcert, err := tpm.GetEKCert()
//	if err != nil {
//		fmt.Printf("Error: %s", err)
//	}
	aikpub, aikblob, err := tpm.GenerateAIK()	
	if err != nil {
		fmt.Printf("Error: %s", err)
	}
//	asymenc, symenc, err := attestation.GenerateChallenge(nil, ekcert, aikpub, []byte{0x01, 0x02, 0x03})
//	if err != nil {
//		fmt.Printf("Error: %s", err)
//	}
//	_, err = tpm.ValidateAIK(aikblob, asymenc, symenc)
//	if err != nil {
//		fmt.Printf("Error: %s", err)
//	}
	_, log, err := tpm.GetQuote(aikpub, aikblob, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	for _, entry := range(log) {
		fmt.Printf(" %s\n", string(entry.Event))
	}
}
