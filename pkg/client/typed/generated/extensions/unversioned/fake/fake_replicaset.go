/*
Copyright 2016 The Kubernetes Authors All rights reserved.

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

package fake

import (
	api "k8s.io/kubernetes/pkg/api"
	extensions "k8s.io/kubernetes/pkg/apis/extensions"
	core "k8s.io/kubernetes/pkg/client/testing/core"
	labels "k8s.io/kubernetes/pkg/labels"
	watch "k8s.io/kubernetes/pkg/watch"
)

// FakeReplicaSets implements ReplicaSetInterface
type FakeReplicaSets struct {
	Fake *FakeExtensions
	ns   string
}

func (c *FakeReplicaSets) Create(replicaSet *extensions.ReplicaSet) (result *extensions.ReplicaSet, err error) {
	obj, err := c.Fake.
		Invokes(core.NewCreateAction("replicasets", c.ns, replicaSet), &extensions.ReplicaSet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.ReplicaSet), err
}

func (c *FakeReplicaSets) Update(replicaSet *extensions.ReplicaSet) (result *extensions.ReplicaSet, err error) {
	obj, err := c.Fake.
		Invokes(core.NewUpdateAction("replicasets", c.ns, replicaSet), &extensions.ReplicaSet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.ReplicaSet), err
}

func (c *FakeReplicaSets) UpdateStatus(replicaSet *extensions.ReplicaSet) (*extensions.ReplicaSet, error) {
	obj, err := c.Fake.
		Invokes(core.NewUpdateSubresourceAction("replicasets", "status", c.ns, replicaSet), &extensions.ReplicaSet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.ReplicaSet), err
}

func (c *FakeReplicaSets) Delete(name string, options *api.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(core.NewDeleteAction("replicasets", c.ns, name), &extensions.ReplicaSet{})

	return err
}

func (c *FakeReplicaSets) DeleteCollection(options *api.DeleteOptions, listOptions api.ListOptions) error {
	action := core.NewDeleteCollectionAction("events", c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &extensions.ReplicaSetList{})
	return err
}

func (c *FakeReplicaSets) Get(name string) (result *extensions.ReplicaSet, err error) {
	obj, err := c.Fake.
		Invokes(core.NewGetAction("replicasets", c.ns, name), &extensions.ReplicaSet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*extensions.ReplicaSet), err
}

func (c *FakeReplicaSets) List(opts api.ListOptions) (result *extensions.ReplicaSetList, err error) {
	obj, err := c.Fake.
		Invokes(core.NewListAction("replicasets", c.ns, opts), &extensions.ReplicaSetList{})

	if obj == nil {
		return nil, err
	}

	label := opts.LabelSelector
	if label == nil {
		label = labels.Everything()
	}
	list := &extensions.ReplicaSetList{}
	for _, item := range obj.(*extensions.ReplicaSetList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested replicaSets.
func (c *FakeReplicaSets) Watch(opts api.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(core.NewWatchAction("replicasets", c.ns, opts))

}
