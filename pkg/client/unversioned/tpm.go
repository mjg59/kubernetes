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
        "k8s.io/kubernetes/pkg/apimachinery/registered"
	"k8s.io/kubernetes/pkg/apis/tpm"
	"k8s.io/kubernetes/pkg/watch"
)

const (
	TpmResourceName string = "tpms"
)

type TpmNamespacer interface {
	Tpms() TpmInterface
}

type TpmClient struct {
	*RESTClient
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
	client    *TpmClient
}

// Tpms should implement tpmInterface
var _ TpmInterface = &Tpms{}

func setTpmDefaults(config *Config) error {
	// if experimental group is not registered, return an error
	g, err := registered.Group(tpm.GroupName)
	if err != nil {
		return err
	}
	config.APIPath = defaultAPIPath
	if config.UserAgent == "" {
		config.UserAgent = DefaultKubernetesUserAgent()
	}
	// TODO: Unconditionally set the config.Version, until we fix the config.
	//if config.Version == "" {
	copyGroupVersion := g.GroupVersion
	config.GroupVersion = &copyGroupVersion
	//}

	config.Codec = api.Codecs.LegacyCodec(*config.GroupVersion)
	if config.QPS == 0 {
		config.QPS = 5
	}
	if config.Burst == 0 {
		config.Burst = 10
	}
	return nil
}

func newTpmClient(c *Config) (*TpmClient, error) {
	config := *c
	if err := setTpmDefaults(&config); err != nil {
		return nil, err
	}
	client, err := RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &TpmClient{client}, nil
}	

func newTpms(c *TpmClient) *Tpms {
	return &Tpms{
		client:    c,
	}
}

func (c *Tpms) Get(name string) (*tpm.Tpm, error) {
	result := &tpm.Tpm{}
	err := c.client.Get().
		Resource(TpmResourceName).
		Name(name).
		Do().
		Into(result)

	return result, err
}

func (c *Tpms) List(opts api.ListOptions) (*tpm.TpmList, error) {
	result := &tpm.TpmList{}
	err := c.client.Get().
		Resource(TpmResourceName).
		VersionedParams(&opts, api.Scheme).
		Do().
		Into(result)

	return result, err
}

func (c *Tpms) Create(cfg *tpm.Tpm) (*tpm.Tpm, error) {
	result := &tpm.Tpm{}
	err := c.client.Post().
		Resource(TpmResourceName).
		Body(cfg).
		Do().
		Into(result)

	return result, err
}

func (c *Tpms) Delete(name string) error {
	return c.client.Delete().
		Resource(TpmResourceName).
		Name(name).
		Do().
		Error()
}

func (c *Tpms) Update(cfg *tpm.Tpm) (*tpm.Tpm, error) {
	result := &tpm.Tpm{}

	err := c.client.Put().
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
		Resource(TpmResourceName).
		VersionedParams(&opts, api.Scheme).
		Watch()
}
