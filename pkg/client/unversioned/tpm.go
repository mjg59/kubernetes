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

package unversioned

import (
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/tpm"
	"k8s.io/kubernetes/pkg/watch"
)

const (
	TpmResourceName string = "tpms"
)

type TpmNamespacer interface {
	Tpms() TpmInterface
}

type TpmInterface interface {
	Get(string) (*tpm.Tpm, error)
	List(opts api.ListOptions) (*tpm.TpmList, error)
	Create(*tpm.Tpm) (*tpm.Tpm, error)
	Delete(string) error
	Update(*tpm.Tpm) (*tpm.Tpm, error)
	Watch(api.ListOptions) (watch.Interface, error)
}

type Tpms struct {
	client    *Client
}

// Tpms should implement tpmInterface
var _ TpmInterface = &Tpms{}

func newTpms(c *Client) *Tpms {
	return &Tpms{
		client:    c,
	}
}

func (c *Tpms) Get(name string) (*tpm.Tpm, error) {
	result := &tpm.Tpm{}
	err := c.client.Get().
		Namespace("").
		Resource(TpmResourceName).
		Name(name).
		Do().
		Into(result)

	return result, err
}

func (c *Tpms) List(opts api.ListOptions) (*tpm.TpmList, error) {
	result := &tpm.TpmList{}
	err := c.client.Get().
		Namespace("").
		Resource(TpmResourceName).
		VersionedParams(&opts, api.Scheme).
		Do().
		Into(result)

	return result, err
}

func (c *Tpms) Create(cfg *tpm.Tpm) (*tpm.Tpm, error) {
	result := &tpm.Tpm{}
	err := c.client.Post().
		Namespace("").
		Resource(TpmResourceName).
		Body(cfg).
		Do().
		Into(result)

	return result, err
}

func (c *Tpms) Delete(name string) error {
	return c.client.Delete().
		Namespace("").
		Resource(TpmResourceName).
		Name(name).
		Do().
		Error()
}

func (c *Tpms) Update(cfg *tpm.Tpm) (*tpm.Tpm, error) {
	result := &tpm.Tpm{}

	err := c.client.Put().
		Namespace("").
		Resource(TpmResourceName).
		Name(cfg.Name).
		Body(cfg).
		Do().
		Into(result)

	return result, err
}

func (c *Tpms) Watch(opts api.ListOptions) (watch.Interface, error) {
	return c.client.Get().
		Prefix("watch").
		Namespace("").
		Resource(TpmResourceName).
		VersionedParams(&opts, api.Scheme).
		Watch()
}
