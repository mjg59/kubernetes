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

package testclient

import (
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/tpm"
	"k8s.io/kubernetes/pkg/watch"
)

const (
	tpmDataResourceName string = "tpms"
)

// FakeTpms implements TpmInterface. Meant to be embedded into a struct to get a default
// implementation. This makes faking out just the method you want to test easier.
type FakeTpms struct {
	Fake      *Fake
}

func (c *FakeTpms) Get(name string) (*tpm.Tpm, error) {
	obj, err := c.Fake.Invokes(NewGetAction(configMapResourceName, "", name), &tpm.Tpm{})
	if obj == nil {
		return nil, err
	}

	return obj.(*tpm.Tpm), err
}

func (c *FakeTpms) List(opts api.ListOptions) (*tpm.TpmList, error) {
	obj, err := c.Fake.Invokes(NewListAction(configMapResourceName, "", opts), &tpm.TpmList{})
	if obj == nil {
		return nil, err
	}

	return obj.(*tpm.TpmList), err
}

func (c *FakeTpms) Create(cfg *tpm.Tpm) (*tpm.Tpm, error) {
	obj, err := c.Fake.Invokes(NewCreateAction(configMapResourceName, "", cfg), cfg)
	if obj == nil {
		return nil, err
	}

	return obj.(*tpm.Tpm), err
}

func (c *FakeTpms) Update(cfg *tpm.Tpm) (*tpm.Tpm, error) {
	obj, err := c.Fake.Invokes(NewUpdateAction(configMapResourceName, "", cfg), cfg)
	if obj == nil {
		return nil, err
	}

	return obj.(*tpm.Tpm), err
}

func (c *FakeTpms) Delete(name string) error {
	_, err := c.Fake.Invokes(NewDeleteAction(configMapResourceName, "", name), &tpm.Tpm{})
	return err
}

func (c *FakeTpms) Watch(opts api.ListOptions) (watch.Interface, error) {
	return c.Fake.InvokesWatch(NewWatchAction(configMapResourceName, "", opts))
}
