/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package v1

import (
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
)

// Information about a specific TPM
type Tpm struct {
	unversioned.TypeMeta `json:",inline"`
	// Standard object metadata; More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata.
	api.ObjectMeta `json:"metadata,omitempty"`
	// The TPM's EK certificate
	EKCert []byte `json:"ekcert,omitempty"`
	// The encrypted AIK keyblob
	AIKBlob []byte `json:"aikblob,omitempty"`
	// The public half of AIK
	AIKPub []byte `json:"aikpub,omitempty"`
	// The current address associated with the TPM
	Address string `json:"address,omitempty"`
}

// List of all known TPMs
type TpmList struct {
	unversioned.TypeMeta `json:",inline"`
	//More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	unversioned.ListMeta `json:"metadata,omitempty"`
	// Items is the list of Tpm objects
	Items [] Tpm `json:"items,omitempty"`
}
