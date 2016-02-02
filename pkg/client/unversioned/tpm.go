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
	"k8s.io/kubernetes/pkg/watch"
)

const (
	TpmResourceName string = "tpms"
)

type TpmsInterface interface {
	Tpms() TpmInterface
}

type TpmInterface interface {
	Get(string) (*api.Tpm, error)
	List(opts api.ListOptions) (*api.TpmList, error)
	Create(*api.Tpm) (*api.Tpm, error)
	Delete(string) error
	Update(*api.Tpm) (*api.Tpm, error)
	Watch(api.ListOptions) (watch.Interface, error)
}

type tpms struct {
	client    *Client
}

func newTpms(c *Client) *tpms {
	return &tpms{c}
}

func (c *tpms) Get(name string) (*api.Tpm, error) {
	result := &api.Tpm{}
	err := c.client.Get().
		Resource(TpmResourceName).
		Name(name).
		Do().
		Into(result)

	return result, err
}

func (c *tpms) List(opts api.ListOptions) (*api.TpmList, error) {
	result := &api.TpmList{}
	err := c.client.Get().
		Resource(TpmResourceName).
		VersionedParams(&opts, api.ParameterCodec).
		Do().
		Into(result)

	return result, err
}

func (c *tpms) Create(cfg *api.Tpm) (*api.Tpm, error) {
	result := &api.Tpm{}
	err := c.client.Post().
		Resource(TpmResourceName).
		Body(cfg).
		Do().
		Into(result)

	return result, err
}

func (c *tpms) Delete(name string) error {
	return c.client.Delete().
		Resource(TpmResourceName).
		Name(name).
		Do().
		Error()
}

func (c *tpms) Update(cfg *api.Tpm) (*api.Tpm, error) {
	result := &api.Tpm{}

	err := c.client.Put().
		Resource(TpmResourceName).
		Name(cfg.Name).
		Body(cfg).
		Do().
		Into(result)

	return result, err
}

func (c *tpms) Watch(opts api.ListOptions) (watch.Interface, error) {
	return c.client.Get().
		Prefix("watch").
		Resource(TpmResourceName).
		VersionedParams(&opts, api.ParameterCodec).
		Watch()
}
