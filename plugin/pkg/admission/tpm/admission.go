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
	"fmt"
	"io"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
        apierrors "k8s.io/kubernetes/pkg/api/errors"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/kubernetes/pkg/util/tpm"
)

func init() {
	admission.RegisterPlugin("TPMAdmit", func(client client.Interface, config io.Reader) (admission.Interface, error) {
		return NewTPMAdmit(client), nil
	})	
}

// TPMAdmit is an implementation of admission.Interface which performs TPM-based validation of the request
type tpmAdmit struct{
	handler tpm.TPMHandler
}

func (t *tpmAdmit) Admit(a admission.Attributes) (err error) {
	if a.GetOperation() != admission.Create  || a.GetKind() != api.Kind("Node") {
		return nil
	}
	node, ok := a.GetObject().(*api.Node)
	if !ok {
		return apierrors.NewBadRequest("Resource was marked with kind Node but was unable to be converted")
	}
	glog.Errorf("Getting node address")
	address, err := nodeutil.GetNodeHostIP(node)
	if err != nil{
		return admission.NewForbidden(a, err)
	}
	glog.Errorf("Node address is %s", address.String())
	tpmdata, err := t.handler.Get(address.String(), true)
	if err != nil {
		return admission.NewForbidden(a, fmt.Errorf("Unable to obtain TPM object: %p", err))
	}
	glog.Errorf("Requesting quote")
	quote, _, err := tpm.Quote(tpmdata)
	if err != nil {
		glog.Errorf("Invalid quote")
		return admission.NewForbidden(a, fmt.Errorf("Invalid quote provided: %p", err))
	}
	glog.Errorf("Got valid quote")
	if !bytes.Equal(quote[0], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		glog.Errorf("Invalid PCR")
		return admission.NewForbidden(a, fmt.Errorf("Invalid quote provided"))
	}
	return nil
}

func (tpmAdmit) Handles(operation admission.Operation) bool {
	return true
}

// NewTPMAdmit creates a new TPMAdmit handler
func NewTPMAdmit(c client.Interface) admission.Interface {
	var tpmhandler tpm.TPMHandler
	tpmhandler.Setup(c)
	return &tpmAdmit{
		handler: tpmhandler,
	}
}
