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
	"fmt"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/rest"
	"k8s.io/kubernetes/pkg/apis/tpm"
	"k8s.io/kubernetes/pkg/apis/tpm/validation"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/validation/field"
)

// strategy implements behavior for Tpm objects
type strategy struct {
	runtime.ObjectTyper
	api.NameGenerator
}

// Strategy is the default logic that applies when creating and updating Tpm
// objects via the REST API.
var Strategy = strategy{api.Scheme, api.SimpleNameGenerator}

// Strategy should implement rest.RESTCreateStrategy
var _ rest.RESTCreateStrategy = Strategy

// Strategy should implement rest.RESTUpdateStrategy
var _ rest.RESTUpdateStrategy = Strategy

func (strategy) NamespaceScoped() bool {
	return false
}

func (strategy) PrepareForCreate(obj runtime.Object) {
	_ = obj.(*tpm.Tpm)
}

func (strategy) Validate(ctx api.Context, obj runtime.Object) field.ErrorList {
	cfg := obj.(*tpm.Tpm)

	return validation.ValidateTpm(cfg)
}

// Canonicalize normalizes the object after validation.
func (strategy) Canonicalize(obj runtime.Object) {
}

func (strategy) AllowCreateOnUpdate() bool {
	return false
}

func (strategy) PrepareForUpdate(newObj, oldObj runtime.Object) {
	_ = oldObj.(*tpm.Tpm)
	_ = newObj.(*tpm.Tpm)
}

func (strategy) AllowUnconditionalUpdate() bool {
	return true
}

func (strategy) ValidateUpdate(ctx api.Context, newObj, oldObj runtime.Object) field.ErrorList {
	oldCfg, newCfg := oldObj.(*tpm.Tpm), newObj.(*tpm.Tpm)

	return validation.ValidateTpmUpdate(newCfg, oldCfg)
}

// TpmToSelectableFields returns a field set that represents the object for matching purposes.
func TpmToSelectableFields(cfg *tpm.Tpm) fields.Set {
	return generic.ObjectMetaFieldsSet(cfg.ObjectMeta, true)
}

// MatchTpm returns a generic matcher for a given label and field selector.
func MatchTpm(label labels.Selector, field fields.Selector) generic.Matcher {
	return &generic.SelectionPredicate{
		Label: label,
		Field: field,
		GetAttrs: func(obj runtime.Object) (labels.Set, fields.Set, error) {
			cfg, ok := obj.(*tpm.Tpm)
			if !ok {
				return nil, nil, fmt.Errorf("given object is not of type Tpm")
			}

			return labels.Set(cfg.ObjectMeta.Labels), TpmToSelectableFields(cfg), nil
		},
	}
}
