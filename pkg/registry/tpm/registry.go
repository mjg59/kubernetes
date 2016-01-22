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

package tpm

import (
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/rest"
	"k8s.io/kubernetes/pkg/apis/tpm"
	"k8s.io/kubernetes/pkg/watch"
)

// Registry is an interface for things that know how to store Tpm.
type Registry interface {
	ListTpm(ctx api.Context, options *api.ListOptions) (*tpm.TpmList, error)
	WatchTpm(ctx api.Context, options *api.ListOptions) (watch.Interface, error)
	GetTpm(ctx api.Context, name string) (*tpm.Tpm, error)
	CreateTpm(ctx api.Context, cfg *tpm.Tpm) (*tpm.Tpm, error)
	UpdateTpm(ctx api.Context, cfg *tpm.Tpm) (*tpm.Tpm, error)
	DeleteTpm(ctx api.Context, name string) error
}

// storage puts strong typing around storage calls
type storage struct {
	rest.StandardStorage
}

// NewRegistry returns a new Registry interface for the given Storage. Any mismatched
// types will panic.
func NewRegistry(s rest.StandardStorage) Registry {
	return &storage{s}
}

func (s *storage) ListTpm(ctx api.Context, options *api.ListOptions) (*tpm.TpmList, error) {
	obj, err := s.List(ctx, options)
	if err != nil {
		return nil, err
	}

	return obj.(*tpm.TpmList), err
}

func (s *storage) WatchTpm(ctx api.Context, options *api.ListOptions) (watch.Interface, error) {
	return s.Watch(ctx, options)
}

func (s *storage) GetTpm(ctx api.Context, name string) (*tpm.Tpm, error) {
	obj, err := s.Get(ctx, name)
	if err != nil {
		return nil, err
	}

	return obj.(*tpm.Tpm), nil
}

func (s *storage) CreateTpm(ctx api.Context, cfg *tpm.Tpm) (*tpm.Tpm, error) {
	obj, err := s.Create(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return obj.(*tpm.Tpm), nil
}

func (s *storage) UpdateTpm(ctx api.Context, cfg *tpm.Tpm) (*tpm.Tpm, error) {
	obj, _, err := s.Update(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return obj.(*tpm.Tpm), nil
}

func (s *storage) DeleteTpm(ctx api.Context, name string) error {
	_, err := s.Delete(ctx, name, nil)

	return err
}
