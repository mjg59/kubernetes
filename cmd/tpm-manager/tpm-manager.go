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

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/pflag"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	"k8s.io/kubernetes/pkg/client/restclient"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	//        "k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/controller"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/flag"
	nodeutil "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/kubernetes/pkg/util/tpm"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/pkg/watch"
)

const untrusted string = "com.coreos.tpm/untrusted"

// set a node's untrusted state
func setUntrusted(node *api.Node, untrusted bool) {
	taints, err := api.GetTaintsFromNodeAnnotations(node.Annotations)
	if err != nil {
		glog.Errorf("Unable to invalidate node %v", node.Name)
		return
	}
	newTaints := []api.Taint{}
	untrustedTaint := api.Taint{
		Key:    "untrusted",
		Value:  "true",
		Effect: api.TaintEffectNoSchedule,
	}

	for _, taint := range taints {
		if taint.Key == "Untrusted" {
			continue
		}
		newTaints = append(newTaints, taint)
	}

	if untrusted == true {
		newTaints = append(newTaints, untrustedTaint)
	}

	jsonContent, err := json.Marshal(newTaints)
	if err != nil {
		glog.Errorf("Unable to marshal new taint state: %v", err)
		return
	}
	node.Annotations[api.TaintsAnnotationKey] = string(jsonContent)
}

func verifyNode(node *api.Node) (err error) {
	address, err := nodeutil.GetNodeHostIP(node)
	if err != nil {
		return err
	}
	host := fmt.Sprintf("%s:23179", address.String())
	tpmdata, err := manager.tpmhandler.Get(host, manager.allowunknown)
	if err != nil {
		glog.Errorf("Unable to obtain TPM data for node %s: %v", address.String(), err)
		setUntrusted(node, true)
		return nil
	}
	quote, log, err := tpm.Quote(tpmdata)
	if err != nil {
		glog.Errorf("Unable to obtain TPM quote for node %s: %v", address.String(), err)
		setUntrusted(node, true)
		return nil
	}

	pcrconfigs := make([]map[string]tpm.PCRConfig, 0)
	if manager.pcrconfig != "" {
		pcrdata := make(map[string]tpm.PCRConfig)
		pcrconfig, err := ioutil.ReadFile(manager.pcrconfig)
		if err != nil {
			glog.Errorf("Unable to read valid PCR configuration %s: %v", manager.pcrconfig, err)
		}
		err = json.Unmarshal(pcrconfig, &pcrdata)
		if err != nil {
			glog.Errorf("Unable to parse valid PCR configuration %s: %v", manager.pcrconfig, err)
		}
		for pcr, _ := range pcrdata {
			pcrtmp := pcrdata[pcr]
			pcrtmp.Source = manager.pcrconfig
			pcrdata[pcr] = pcrtmp
		}
		pcrconfigs = append(pcrconfigs, pcrdata)
	} else if manager.pcrconfigdir != "" {
		err = filepath.Walk(manager.pcrconfigdir, func(path string, f os.FileInfo, err error) error {
			if f.IsDir() {
				return nil
			}
			pcrconfig, err := ioutil.ReadFile(path)
			if err != nil {
				glog.Errorf("Unable to read PCR configuration %s: %v", path, err)
				return err
			}
			pcrdata := make(map[string]tpm.PCRConfig)
			err = json.Unmarshal(pcrconfig, &pcrdata)
			if err != nil {
				glog.Errorf("Unable to parse valid PCR configuration %s: %v", path, err)
				return err
			}
			for pcr, _ := range pcrdata {
				pcrtmp := pcrdata[pcr]
				pcrtmp.Source = path
				pcrdata[pcr] = pcrtmp
			}
			pcrconfigs = append(pcrconfigs, pcrdata)
			return nil
		})
	} else {
		pcrconfigs, err = manager.tpmhandler.GetPolicies()
		if err != nil {
			glog.Errorf("Unable to obtain PCR configuration: %v", err)
			setUntrusted(node, true)
			return nil
		}
	}

	err = tpm.ValidateLog(log, quote)
	if err != nil {
		glog.Errorf("TPM event log does not match quote for node %s", address.String())
		setUntrusted(node, true)
		return nil
	}

	logstate, err := tpm.ValidatePCRs(log, quote, pcrconfigs)
	jsonlog, _ := json.Marshal(logstate)
	if node.ObjectMeta.Annotations == nil {
		node.ObjectMeta.Annotations = make(map[string]string)
	}
	node.ObjectMeta.Annotations["com.coreos.tpm/logstate"] = string(jsonlog)
	if err != nil {
		glog.Errorf("TPM quote PCRs don't validate for node %s", address.String())
		setUntrusted(node, true)
		return nil
	}

	glog.Errorf("TPM quote for node %s validates", address.String())

	setUntrusted(node, false)
	return nil
}

func verifyAndUpdate(node *api.Node) {
	verifyNode(node)
	newstate := node.ObjectMeta.Annotations[untrusted]
	newnode, err := manager.client.Nodes().Get(node.Name)
	if err != nil {
		glog.Errorf("Unable to obtain node state for %s: %v", node.Name, err)
		return
	}
	if newnode.ObjectMeta.Annotations == nil {
		newnode.ObjectMeta.Annotations = make(map[string]string)
	}
	currenttime := time.Now().Unix()

	if newnode.ObjectMeta.Annotations[untrusted] != newstate {
		if newstate == "true" {
			newnode.ObjectMeta.Annotations["com.coreos.tpm/untrustedsince"] = strconv.FormatInt(currenttime, 10)
			newnode.ObjectMeta.Annotations["com.coreos.tpm/trustedsince"] = ""
		} else {
			newnode.ObjectMeta.Annotations["com.coreos.tpm/untrustedsince"] = ""
			newnode.ObjectMeta.Annotations["com.coreos.tpm/trustedsince"] = strconv.FormatInt(currenttime, 10)
		}
	}

	newnode.ObjectMeta.Annotations["com.coreos.tpm/validationtime"] = strconv.FormatInt(currenttime, 10)
	newnode.ObjectMeta.Annotations[untrusted] = newstate
	newnode.ObjectMeta.Annotations["com.coreos.tpm/logstate"] = node.ObjectMeta.Annotations["com.coreos.tpm/logstate"]
	newnode, err = manager.client.Nodes().Update(newnode)
	if err != nil {
		glog.Errorf("Unable to update node state for %s: %v", node.Name, err)
		return
	}
}

func verifyAllNodes() {
	nodes, err := manager.client.Nodes().List(api.ListOptions{})
	if err != nil {
		return
	}
	for _, node := range nodes.Items {
		verifyAndUpdate(&node)
	}
}

func reverify(delay int) {
	for range time.Tick(time.Second * time.Duration(delay)) {
		verifyAllNodes()
	}
}

type TPMManager struct {
	Master       string
	Kubeconfig   string
	tpmhandler   tpm.TPMHandler
	pcrconfig    string
	pcrconfigdir string
	allowunknown bool
	recurring    int
	client       *client.Client
	policyTimer  *time.Timer
}

var manager TPMManager

func addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&manager.Master, "master", manager.Master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&manager.Kubeconfig, "kubeconfig", manager.Kubeconfig, "Path to kubeconfig file with authorization and master location information.")
	fs.StringVar(&manager.pcrconfig, "pcrconfig", manager.pcrconfig, "Path to a single PCR config file")
	fs.StringVar(&manager.pcrconfigdir, "pcrconfigdir", manager.pcrconfigdir, "Path to a PCR config directory")
	fs.BoolVar(&manager.allowunknown, "allowunknown", false, "Allow unknown TPMs to join the cluster")
	fs.IntVar(&manager.recurring, "reverify", 0, "Periodocally reverify nodes after this many seconds")
}

func main() {
	var tpmhandler tpm.TPMHandler
	var config restclient.Config
	addFlags(pflag.CommandLine)
	flag.InitFlags()
	//	config, err := clientcmd.BuildConfigFromFlags(manager.Master, manager.Kubeconfig)
	err := client.SetKubernetesDefaults(&config)
	if err != nil {
		fmt.Errorf("Unable to create client configuration: %v", err)
	}
	config.Host = "http://localhost:8080"
	client, err := client.New(&config)
	if err != nil {
		fmt.Errorf("Unable to create client: %v", err)
	}
	tpmhandler.Setup(&config)

	_, nodeController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return client.Nodes().List(options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return client.Nodes().Watch(options)
			},
		},
		&api.Node{},
		controller.NoResyncPeriodFunc(),
		framework.ResourceEventHandlerFuncs{
			AddFunc:    nodeAddFn,
			UpdateFunc: nodeUpdateFn,
			DeleteFunc: nodeDeleteFn,
		},
	)

	_, policyController := framework.NewInformer(
		&cache.ListWatch{
			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
				return tpmhandler.PolicyClient.List(&options)
			},
			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
				return tpmhandler.PolicyClient.Watch(&options)
			},
		},
		&api.Node{},
		controller.NoResyncPeriodFunc(),
		framework.ResourceEventHandlerFuncs{
			AddFunc:    policyAddFn,
			UpdateFunc: policyUpdateFn,
			DeleteFunc: policyDeleteFn,
		},
	)

	manager.client = client
	manager.tpmhandler = tpmhandler
	if manager.recurring != 0 {
		go reverify(manager.recurring)
	}
	fmt.Printf("Starting\n")
	go nodeController.Run(wait.NeverStop)
	go policyController.Run(wait.NeverStop)
	select {}
	fmt.Printf("Returned\n")
}

func nodeAddFn(obj interface{}) {
	fmt.Printf("New node\n")
	node, ok := obj.(*api.Node)
	if !ok {
		return
	}
	fmt.Printf("Verifying\n")
	verifyAndUpdate(node)
}

func nodeUpdateFn(oldObj, newObj interface{}) {
}

func nodeDeleteFn(obj interface{}) {
}

func scheduleVerification() {
	if manager.policyTimer != nil {
		manager.policyTimer.Stop()
	}
	manager.policyTimer = time.AfterFunc(time.Second, verifyAllNodes)
}

func policyAddFn(obj interface{}) {
	fmt.Printf("New policy\n")
	scheduleVerification()
}

func policyUpdateFn(oldobj, newobj interface{}) {
	fmt.Printf("Updated policy\n")
	scheduleVerification()
}

func policyDeleteFn(obj interface{}) {
	fmt.Printf("Delteed policy\n")
	scheduleVerification()
}
