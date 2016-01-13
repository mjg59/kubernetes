/*
Copyright 2014 The Kubernetes Authors All rights reserved.
Copyright 2015 CoreOS, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package admit

import (
	"bytes"
	"crypto/rand"
	"io"

	"k8s.io/kubernetes/pkg/api"
        apierrors "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/admission"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"github.com/coreos/go-tspi/attestation"
	"github.com/coreos/go-tspi/tpmclient"
)

func init() {
	admission.RegisterPlugin("TPMAdmit", func(client client.Interface, config io.Reader) (admission.Interface, error) {
		return NewTPMAdmit(), nil
	})
}

// TPMAdmit is an implementation of admission.Interface which performs TPM-based validation of the request
type tpmAdmit struct{}

func (tpmAdmit) Admit(a admission.Attributes) (err error) {
	if a.GetOperation() != admission.Create  || a.GetKind() != api.Kind("Node") {
		return nil
	}
	node, ok := a.GetObject().(*api.Node)
	if !ok {
		return apierrors.NewBadRequest("Resource was marked with kind Node but was unable to be converted")
	}
	tpm := tpmclient.New(node.Status.Addresses[0].Address)
	ekcert, err := tpm.GetEKCert()
	if err != nil {
		return err
	}
	err = attestation.VerifyEKCert(ekcert)
	if err != nil {
		return err
	}
	aikpub, aikblob, err := tpm.GenerateAIK()
	if err != nil {
		return err
	}
	secret := make([]byte, 16)
	_, err = rand.Read(secret)
	if err != nil {
		return err
	}
	aikpub, aikblob, err = tpm.GenerateAIK()
	if err != nil {
		return err
	}
	asymenc, symenc, err := attestation.GenerateChallenge(nil, ekcert, aikpub, secret)
	if err != nil {
		return err
	}
	response, err := tpm.ValidateAIK(aikblob, asymenc, symenc)
	if err != nil {
		return err
	}
	if !bytes.Equal(response[:], secret) {
		return apierrors.NewBadRequest("AIK could not be validated")
	}
	quote, _, err := tpm.GetQuote(aikpub, aikblob, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	if err != nil {
		return err
	}
	if !bytes.Equal(quote[0], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		return apierrors.NewBadRequest("Invalid quote provided")
	}
	// Stash aikpub and aikblob somewhere in the Node data
	return nil
}

func (tpmAdmit) Handles(operation admission.Operation) bool {
	return true
}

// NewTPMAdmit creates a new TPMAdmit handler
func NewTPMAdmit() admission.Interface {
	return new(tpmAdmit)
}
