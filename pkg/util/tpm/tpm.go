package tpm

import (
	"bytes"
	"crypto/sha1"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/coreos/go-tspi/tpmclient"
	"github.com/coreos/go-tspi/tspiconst"
	"github.com/coreos/go-tspi/verification"
	"github.com/golang/glog"
        "k8s.io/kubernetes/pkg/api"
        client "k8s.io/kubernetes/pkg/client/unversioned"
)

type TPMHandler struct {
	tpms client.TpmInterface
}

func (t *TPMHandler) Setup(c client.Interface) error {
	t.tpms = c.Tpms()
	return nil
}

func (t *TPMHandler) Get(address string, allowEmpty bool) (*api.Tpm, error) {
	var tpm *api.Tpm

	c := tpmclient.New(address)
	ekcert, err := c.GetEKCert()

	if err != nil {
		return nil, err
	}

	eksha := sha1.Sum(ekcert)
	ekhash := hex.EncodeToString(eksha[:])
	tpm, err = t.tpms.Get(ekhash)

	if err != nil {
		if (allowEmpty == false) {
			return nil, nil
		}
		err = verification.VerifyEKCert(ekcert)
		if err != nil {
			return nil, err
		}
		tpm = &api.Tpm {
			ObjectMeta: api.ObjectMeta{
				Name: ekhash,
				Namespace: "",
			},
			EKCert: ekcert,
		}
		tpm, err = t.tpms.Create(tpm)
		if err != nil {
			return nil, err
		}
	}

	if len(tpm.AIKPub) == 0 || len(tpm.AIKBlob) == 0 {
		secret := make([]byte, 16)
		_, err = rand.Read(secret)
		if err != nil {
			return nil, err
		}
		aikpub, aikblob, err := c.GenerateAIK()
		if err != nil {
			return nil, err
		}
		asymenc, symenc, err := verification.GenerateChallenge(ekcert, aikpub, secret)
		if err != nil {
			return nil, err
		}
		response, err := c.ValidateAIK(aikblob, asymenc, symenc)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(response[:], secret) {
			return nil, fmt.Errorf("AIK could not be validated")
		}
		tpm.AIKPub = aikpub
		tpm.AIKBlob = aikblob
		tpm, err = t.tpms.Update(tpm)
		if err != nil {
			return nil, err
		}
	}

	tpm.Address = address
	return tpm, nil
}

func Quote(tpm *api.Tpm) ([][]byte, []tspiconst.Log, error) {
	c := tpmclient.New(tpm.Address)
	quote, log, err := c.GetQuote(tpm.AIKPub, tpm.AIKBlob, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	return quote, log, err
}

func ValidateLogConsistency(log []tspiconst.Log, pcrs []int) error {
	for _, entry := range log {
		for _, pcr := range pcrs {
			if entry.Pcr != pcr {
				continue
			}
			hash := sha1.Sum(entry.Event[:])
			if bytes.Equal(hash[:], entry.PcrValue[:]) {
				continue
			}
			return fmt.Errorf("Log entry is inconsistent with claimed PCR value")
		}
	}

	return nil
}

func ValidateLog(log []tspiconst.Log, quote [][]byte, pcrs []int) error {
	var virt_pcrs [24][20]byte

	for _, entry := range log {
		var tmp [40]byte
		glog.Errorf("Extending PCR %d from %s with %s", entry.Pcr, hex.EncodeToString(virt_pcrs[entry.Pcr][:]), hex.EncodeToString(entry.PcrValue[:]))
		cur := tmp[0:20]
		new := tmp[20:40]
		copy(cur, virt_pcrs[entry.Pcr][:])
		copy(new, entry.PcrValue[:])
		virt_pcrs[entry.Pcr] = sha1.Sum(tmp[:])
		glog.Errorf("New value of PCR %d is %s", entry.Pcr, hex.EncodeToString(virt_pcrs[entry.Pcr][:]))
	}

	for _, pcr := range pcrs {
		if !bytes.Equal(virt_pcrs[pcr][:], quote[pcr]) {
			glog.Errorf("Log for %d doesn't validate: %s %s", pcr, hex.EncodeToString(virt_pcrs[pcr][:]), hex.EncodeToString(quote[pcr]))
			return fmt.Errorf("Log doesn't validate")
		}
	}

	return nil
}

func ValidatePCRs(quote [][]byte, pcrconfig map[string][]string) error {
	glog.Errorf("pcrconfig is %v", pcrconfig)
	for pcrname, _ := range pcrconfig {
		pcr, _ := strconv.Atoi(pcrname)
		glog.Errorf("Checking PCR %d", pcr)
		glog.Errorf("Current value is %s", hex.EncodeToString(quote[pcr]))
		valid := false
		for _, validpcr := range pcrconfig[pcrname] {
			glog.Errorf("Validating against %s", validpcr)
			if validpcr == "*" {
				valid = true
				break
			}
			validHex, err := hex.DecodeString(validpcr)
			if err != nil {
				glog.Errorf("Couldn't parse %s as hex", validpcr)
				return fmt.Errorf("Unable to parse %s in PCR %d", validpcr, pcr)
			}
			if bytes.Equal(validHex, quote[pcr]) {
				glog.Errorf("Valid!")
				valid = true
			}
		}
		if valid != true {
			glog.Errorf("PCR %d is invalid", pcr)
			return fmt.Errorf("PCR %d is invalid", pcr)
		}
	}

	return nil
}
