package tpm

import (
	"bytes"
	"crypto/sha1"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/coreos/go-tspi/tpmclient"
	"github.com/coreos/go-tspi/tspiconst"
	"github.com/coreos/go-tspi/verification"
	"github.com/golang/glog"
        "k8s.io/kubernetes/pkg/api"
//	"k8s.io/kubernetes/pkg/api/errors"
	tpmapi "k8s.io/kubernetes/pkg/apis/tpm"
//	"k8s.io/kubernetes/pkg/client/cache"
        client "k8s.io/kubernetes/pkg/client/unversioned"
//        "k8s.io/kubernetes/pkg/runtime"
//	"k8s.io/kubernetes/pkg/watch"
)

type TPMHandler struct {
//	store cache.Store
	tpms client.TpmInterface
}

func tpmKeyFunc(obj interface{}) (string, error) {
	tpm, ok := obj.(*tpmapi.Tpm);
	if !ok {
		return "", fmt.Errorf("Bad TPM data object")
	}

	eksha := sha1.Sum(tpm.EKCert)
	ekhash := hex.EncodeToString(eksha[:])

	key := fmt.Sprintf("com.coreos/tpm/%s", ekhash)
	glog.Errorf("Key is %s", key);
	return key, nil
}

func (t *TPMHandler) Setup(c client.Interface) error {
	glog.Errorf("Setting up TPMHandler")
	t.tpms = c.Tpms()
//	t.store = cache.NewStore(cache.MetaNamespaceKeyFunc)
//	reflector := cache.NewReflector(
//		&cache.ListWatch{
//			ListFunc: func(options api.ListOptions) (runtime.Object, error) {
//				return c.Tpms().List(options)
//			},
//			WatchFunc: func(options api.ListOptions) (watch.Interface, error) {
//				return c.Tpms().Watch(options)
//			},
//		},
//		&tpmapi.Tpm{},
//		t.store,
//		0,
//	)
//	reflector.Run()
	return nil
}

func (t *TPMHandler) Get(address string, allowEmpty bool) (*tpmapi.Tpm, error) {
	var tpm *tpmapi.Tpm
//	var ok bool

	c := tpmclient.New(address)
	ekcert, err := c.GetEKCert()

	if err != nil {
		glog.Errorf("No ekcert: %v", err)
		return nil, err
	}

	eksha := sha1.Sum(ekcert)
	ekhash := hex.EncodeToString(eksha[:])
	glog.Errorf("Getting %s", ekhash)
	tpm, err = t.tpms.Get(ekhash)
//	tpmobj, exists, err := t.store.GetByKey(ekhash)

//	if exists == false {
//	if errors.IsNotFound(err) {
	if err != nil {
		glog.Errorf("No existing object")
		if (allowEmpty == false) {
			return nil, nil
		}
		err = verification.VerifyEKCert(ekcert)
		if err != nil {
			glog.Errorf("Invalid EKCert")
			return nil, err
		}
		tpm = &tpmapi.Tpm {
			ObjectMeta: api.ObjectMeta{
				Name: ekhash,
				Namespace: "",
			},
			EKCert: ekcert,
		}
//		err = t.store.Add(tpm)
		glog.Errorf("Name is %s", tpm.ObjectMeta.Name)
		tpm, err = t.tpms.Create(tpm)
		if err != nil {
			glog.Errorf("Can't create new tpmdata object: %v", err)
			return nil, err
		}
//	} else if err != nil {
//		glog.Errorf("Can't get tpmdata: %v", err)
//		return nil, err
	}
//		glog.Errorf("Object exists")
//		tpm, ok = tpmobj.(*tpmapi.Tpm)
//		if !ok {
//			glog.Errorf("Bad TPM object")
//			return nil, fmt.Errorf("Bad TPM object")
//		}
//	}

	if tpm.AIKPub == nil || tpm.AIKBlob == nil {
		secret := make([]byte, 16)
		_, err = rand.Read(secret)
		if err != nil {
			glog.Errorf("Can't read random")
			return nil, err
		}
		aikpub, aikblob, err := c.GenerateAIK()
		if err != nil {
			glog.Errorf("Can't generate AIK")
			return nil, err
		}
		asymenc, symenc, err := verification.GenerateChallenge(ekcert, aikpub, secret)
		if err != nil {
			glog.Errorf("Can't generate challenge")
			return nil, err
		}
		response, err := c.ValidateAIK(aikblob, asymenc, symenc)
		if err != nil {
			glog.Errorf("Can't validate AIK")
			return nil, err
		}
		if !bytes.Equal(response[:], secret) {
			glog.Errorf("AIK validation returned invalid secret")
			return nil, fmt.Errorf("AIK could not be validated")
		}
		tpm.AIKPub = aikpub
		tpm.AIKBlob = aikblob
		tpm, err = t.tpms.Update(tpm)
		if err != nil {
			glog.Errorf("Failed to update tpm data")
			return nil, err
		}
	}

	tpm.Address = address
	return tpm, nil
}

func Quote(tpm *tpmapi.Tpm) ([][]byte, []tspiconst.Log, error) {
	c := tpmclient.New(tpm.Address)
	quote, log, err := c.GetQuote(tpm.AIKPub, tpm.AIKBlob, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	return quote, log, err
}
