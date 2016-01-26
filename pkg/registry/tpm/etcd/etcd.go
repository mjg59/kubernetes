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

package etcd

import (
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/tpm"
	tpmregistry "k8s.io/kubernetes/pkg/registry/tpm"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"

	etcdgeneric "k8s.io/kubernetes/pkg/registry/generic/etcd"
)

// REST implements a RESTStorage for Tpm against etcd
type REST struct {
	*etcdgeneric.Etcd
}

// NewREST returns a RESTStorage object that will work with Tpm objects.
func NewREST(s storage.Interface, storageDecorator generic.StorageDecorator) *REST {
	prefix := "/tpms"

	newListFunc := func() runtime.Object { return &tpm.TpmList{} }
	storageInterface := storageDecorator(
		s, 100, &tpm.Tpm{}, prefix, false, newListFunc)

	store := &etcdgeneric.Etcd{
		NewFunc: func() runtime.Object {
			return &tpm.Tpm{}
		},

		// NewListFunc returns an object to store results of an etcd list.
		NewListFunc: newListFunc,

		// Produces a path that etcd understands, to the root of the resource
		// by combining the namespace in the context with the given prefix.
		KeyRootFunc: func(ctx api.Context) string {
			return etcdgeneric.NamespaceKeyRootFunc(ctx, prefix)
		},

		// Produces a path that etcd understands, to the resource by combining
		// the namespace in the context with the given prefix
		KeyFunc: func(ctx api.Context, name string) (string, error) {
			return etcdgeneric.NamespaceKeyFunc(ctx, prefix, name)
		},

		// Retrieves the name field of a Tpm object.
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*tpm.Tpm).Name, nil
		},

		// Matches objects based on labels/fields for list and watch
		PredicateFunc: tpmregistry.MatchTpm,

		QualifiedResource: tpm.Resource("tpms"),

		CreateStrategy: tpmregistry.Strategy,
		UpdateStrategy: tpmregistry.Strategy,

		Storage: storageInterface,
	}
	return &REST{store}
}
