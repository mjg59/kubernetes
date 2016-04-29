package tpm

import (
	"bytes"
	"crypto/sha1"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/coreos/go-tspi/tpmclient"
	"github.com/coreos/go-tspi/tspiconst"
	"github.com/coreos/go-tspi/verification"
	"github.com/mitchellh/mapstructure"
	api "k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/client/restclient"
        client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/client/typed/dynamic"
	"k8s.io/kubernetes/pkg/runtime"
)

type TPMHandler struct {
	tpmclient *dynamic.ResourceClient
	policyclient *dynamic.ResourceClient
}

var TPMResource string = "coreos.com"

type Tpm struct {
	// The TPM's EK certificate
	EKCert []byte
	// The encrypted AIK keyblob
	AIKBlob []byte
	// The public half of AIK
	AIKPub []byte
	// The current address associated with the TPM
	Address string
}

func (t *TPMHandler) Setup(config *restclient.Config) error {
	if err := client.SetKubernetesDefaults(config); err != nil {
		return err
	}
	config.APIPath="apis/coreos.com"
	config.Host="http://localhost:8080"
	tpmclient, err := dynamic.NewClient(config)
	if err != nil {
		return err
	}
	tpmresource := &unversioned.APIResource {
		Kind: "Tpm",
		Name: "tpms",
		Namespaced: true,
	}
	tpmresourceclient := tpmclient.Resource(tpmresource, "default")
	if err != nil {
		return err
	}
	t.tpmclient = tpmresourceclient

	config.APIPath="apis/tpm.coreos.com"
	policyclient, err := dynamic.NewClient(config)
	if err != nil {
		return err
	}
	policyresource := &unversioned.APIResource {
		Kind: "Policy",
		Name: "policys",
		Namespaced: true,
	}
	policyresourceclient := policyclient.Resource(policyresource, "default")
	if err != nil {
		return err
	}
	t.policyclient = policyresourceclient

	return nil
}

func (t *TPMHandler) GetPolicies() ([]map[string]PCRConfig, error) {
	var configs []map[string]PCRConfig
	unstructuredPolicies, err := t.policyclient.List(api.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, unstructuredPolicy := range unstructuredPolicies.Items {
		config := make(map[string]PCRConfig)
		name := unstructuredPolicy.Object["name"].(string)
		policy := unstructuredPolicy.Object["policy"]
		policymap := policy.(map[string]interface{})
		for pcr, unstructuredpcrconfig := range(policymap) {
			var pcrconfig PCRConfig
			err = mapstructure.Decode(unstructuredpcrconfig, &pcrconfig)
			pcrconfig.Source = name
			config[pcr] = pcrconfig
		}
		configs = append(configs, config)
	}
	return configs, nil
}

func (t *TPMHandler) Get(address string, allowEmpty bool) (*Tpm, error) {
	var tpm *Tpm

	c := tpmclient.New(address, 30 * time.Second)
	ekcert, err := c.GetEKCert()

	if err != nil {
		return nil, err
	}

	eksha := sha1.Sum(ekcert)
	ekhash := hex.EncodeToString(eksha[:])
	tpm = &Tpm{}
	unstructuredTpm := &runtime.Unstructured{}
	unstructuredTpm, err = t.tpmclient.Get(ekhash)

	if err != nil {
		if (allowEmpty == false) {
			return nil, fmt.Errorf("TPM does not exist and automatic creation is forbidden")
		}
		err = verification.VerifyEKCert(ekcert)
		if err != nil {
			return nil, err
		}
		tpm = &Tpm {
			EKCert: ekcert,
		}
		unstructuredTpm.Object = make(map[string]interface{})
		unstructuredTpm.Object["kind"] = "Tpm"
		unstructuredTpm.Object["apiVersion"] = "coreos.com/v1"
		unstructuredTpm.Object["EKCert"] = base64.StdEncoding.EncodeToString(tpm.EKCert)
		unstructuredTpm.Object["AIKPub"] = ""
		unstructuredTpm.Object["AIKBlob"] = ""
		metadata := make(map[string]interface{})
		metadata["name"] = ekhash
		unstructuredTpm.Object["metadata"] = metadata

		unstructuredTpm, err = t.tpmclient.Create(unstructuredTpm)
		if err != nil {
			return nil, err
		}
		unstructuredTpm, err = t.tpmclient.Get(ekhash)
		if err != nil {
			return nil, err
		}
	}

	tpm.EKCert, _ = base64.StdEncoding.DecodeString(unstructuredTpm.Object["EKCert"].(string))
	tpm.AIKPub, _ = base64.StdEncoding.DecodeString(unstructuredTpm.Object["AIKPub"].(string))
	tpm.AIKBlob, _ = base64.StdEncoding.DecodeString(unstructuredTpm.Object["AIKBlob"].(string))

	if len(tpm.EKCert) == 0 {
		tpm.EKCert = ekcert
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
		unstructuredTpm.Name = ekhash
		unstructuredTpm.Object["EKCert"] = tpm.EKCert
		unstructuredTpm.Object["AIKPub"] = tpm.AIKPub
		unstructuredTpm.Object["AIKBlob"] = tpm.AIKBlob
		unstructuredTpm, err = t.tpmclient.Update(unstructuredTpm)
		if err != nil {
			return nil, err
		}
	}

	tpm.Address = address
	return tpm, nil
}

func Quote(tpm *Tpm) ([][]byte, []tspiconst.Log, error) {
	c := tpmclient.New(tpm.Address, 30 * time.Second)
	quote, log, err := c.GetQuote(tpm.AIKPub, tpm.AIKBlob, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	return quote, log, err
}

func ValidateLogConsistency(log []tspiconst.Log) error {
	for _, entry := range log {
		hash := sha1.Sum(entry.Event[:])
		if bytes.Equal(hash[:], entry.PcrValue[:]) {
			continue
		}
		return fmt.Errorf("Log entry is inconsistent with claimed PCR value")
	}

	return nil
}

func ValidateLog(log []tspiconst.Log, quote [][]byte) error {
	var virt_pcrs [24][20]byte

	for _, entry := range log {
		var tmp [40]byte
		cur := tmp[0:20]
		new := tmp[20:40]
		copy(cur, virt_pcrs[entry.Pcr][:])
		copy(new, entry.PcrValue[:])
		virt_pcrs[entry.Pcr] = sha1.Sum(tmp[:])
	}

	for pcr, _ := range quote {
		if len(quote[pcr]) == 0 {
			continue
		}
		if !bytes.Equal(virt_pcrs[pcr][:], quote[pcr]) {
			glog.Errorf("Log fails to match for PCR %d", pcr)
			glog.Errorf("%v vs %v", virt_pcrs[pcr], quote[pcr])
			return fmt.Errorf("Log doesn't validate")
		}
	}

	return nil
}

type PCRValue struct {
	Value string
	Description string
}

type PCRConfig struct {
	Source string
	RawValues []PCRValue
	ASCIIValues []PCRDescription
	BinaryValues []PCRDescription
}

type PCRDescription struct {
	Prefix string
	Values []PCRValue
}

type ValidatedLog struct {
	tspiconst.Log
	Valid bool
	Description string
	Source string
}

func ValidateRawPCR(pcrval []byte, valid []PCRValue) bool {
	for _, validpcr := range valid {
		if validpcr.Value == "*" {
			return true
		}
		validHex, err := hex.DecodeString(validpcr.Value)
		if err != nil {
			glog.Errorf("Couldn't parse %s as hex", validpcr)
			continue
		}
		if bytes.Equal(validHex, pcrval) {
			return true
		}
	}
	return false
}

func ValidateBinaryPCR(pcr int, log[]ValidatedLog, values []PCRDescription, source string) {
	for index, logentry := range log {
		var prefix string
		if logentry.Pcr != int32(pcr) {
			continue
		}
		substrs := strings.SplitAfterN(string(logentry.Event), " ", 2)

		if len(substrs) == 2 {
			prefix = substrs[0]
		}
		prefix = strings.Split(string(logentry.Event), " ")[0]
		for _, config := range values {
			if config.Prefix != "" && prefix != config.Prefix {
				continue
			}
			for _, validpcr := range config.Values {
				if validpcr.Value == "*" {
					log[index].Valid = true
					log[index].Description = validpcr.Description
					log[index].Source = source
					continue
				}
				validHex, err := hex.DecodeString(validpcr.Value)
				if err != nil {
					glog.Errorf("Couldn't parse %s as hex", validpcr.Value)
					continue
				}
				if bytes.Equal(validHex, logentry.PcrValue[:]) {
					log[index].Valid = true
					log[index].Description = validpcr.Description
					log[index].Source = source
				}
			}
		}
	}
	return
}

func ValidateASCIIPCR(pcr int, log[]ValidatedLog, values []PCRDescription, source string) {
	for index, logentry := range log {
		var prefix string
		var event string
		// Only verify events of type 13
		if logentry.Eventtype != 13 {
			continue
		}
		if logentry.Pcr != int32(pcr) {
			continue
		}
		substrs := strings.SplitAfterN(string(logentry.Event), " ", 2)

		if len(substrs) == 2 {
			prefix = strings.TrimRight(substrs[0], " ")
			event = substrs[1]
		} else {
			event = substrs[0]
		}
		for _, config := range values {
			if config.Prefix != "" && prefix != config.Prefix {
				continue
			}
			for _, validpcr := range config.Values {
				match, err := regexp.MatchString(validpcr.Value, event)
				if err == nil && match == true {
					log[index].Valid = true
					log[index].Description = validpcr.Description
					log[index].Source = source
					break
				}
			}
		}
	}
	return
}

func ValidatePCRs(log []tspiconst.Log, quote [][]byte, pcrconfig []map[string]PCRConfig) ([]ValidatedLog, error) {
	validatedlog := make([]ValidatedLog, len(log))
	for index, logentry := range log {
		validatedlog[index] = ValidatedLog{logentry, false, "", ""}
	}
	for _, config := range pcrconfig {
		for pcrname, _ := range config {
			pcr, _ := strconv.Atoi(pcrname)
			if len(config[pcrname].RawValues) != 0 {
				valid := ValidateRawPCR(quote[pcr], config[pcrname].RawValues)
				// If the raw PCR is valid then all log entries for that PCR are valid
				if valid == true {
					for index, _ := range(validatedlog) {
						if int(validatedlog[index].Pcr) == pcr {
							validatedlog[index].Valid = true
							validatedlog[index].Source = config[pcrname].Source
						}
					}
					continue
				}
			}

			if len(config[pcrname].BinaryValues) != 0 {
				ValidateBinaryPCR(pcr, validatedlog, config[pcrname].BinaryValues, config[pcrname].Source)
			}

			if len(config[pcrname].ASCIIValues) != 0 {
				ValidateASCIIPCR(pcr, validatedlog, config[pcrname].ASCIIValues, config[pcrname].Source)
			}
		}
	}

	// If any events that haven't been validated, the attestation fails
	for _, logevent := range(validatedlog) {
		if logevent.Valid == false {
			glog.Errorf("PCR state is invalid")
			return validatedlog, fmt.Errorf("PCR state is invalid")
		}
	}

	return validatedlog, nil
}
