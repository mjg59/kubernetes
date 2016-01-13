package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/coreos/go-tspi/tspi"
)

var wellKnown [20]byte

func main () {
	enable := []byte("6")
	activate := []byte("3")
	val, err := ioutil.ReadFile("/sys/class/tpm/tpm0/enabled")
	if os.IsNotExist(err) {
		log.Fatalf("System has no tpm")
	}

	if bytes.Equal(val, []byte("0")) {
		ioutil.WriteFile("/sys/class/tpm/tpm0/device/ppi/request", enable, 0664)
		exec.Command("reboot", "").Run()
	}
	
	val, err = ioutil.ReadFile("/sys/class/tpm/tpm0/active")

	if  bytes.Equal(val, []byte("0")) {
		ioutil.WriteFile("/sys/class/tpm/tpm0/device/ppi/request", activate, 0664)
		exec.Command("reboot", "").Run()
	}

	val, err = ioutil.ReadFile("/sys/class/tpm/tpm0/owned")
	if  bytes.Equal(val, []byte("0")) {
		context, err := tspi.NewContext()
		if err != nil {
			log.Fatalf("Unable to create TSS context")
		}

		context.Connect()
		tpm := context.GetTPM()
		tpmpolicy, err := tpm.GetPolicy(tspi.TSS_POLICY_USAGE)
		if err != nil {
			log.Fatalf("Unable to obtain TPM policy")
		}
		err = tpmpolicy.SetSecret(tspi.TSS_SECRET_MODE_SHA1, wellKnown[:])
		if err != nil {
			log.Fatalf("Unable to set TPM policy")
		}

		srk, err := context.CreateKey(tspi.TSS_KEY_TSP_SRK | tspi.TSS_KEY_AUTHORIZATION)
		if err != nil {
			log.Fatalf("Unable to create SRK")
		}
		keypolicy, err := srk.GetPolicy(tspi.TSS_POLICY_USAGE)
		if err != nil {
			log.Fatalf("Unable to obtain SRK policy")
		}
		err = keypolicy.SetSecret(tspi.TSS_SECRET_MODE_SHA1, wellKnown[:])
		if err != nil {
			log.Fatalf("Unable to set SRK policy")
		}

		err = tpm.TakeOwnership(srk)

		if err != nil {
			log.Fatalf("Unable to take ownership of TPM")
		}
	}

}
