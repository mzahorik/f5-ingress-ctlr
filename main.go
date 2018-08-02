/*
Copyright 2018 Matthew Zahorik <matt.zahorik@gmail.com>

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

// Note: the example only works with the code within the same release/branch.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mzahorik/go-bigip"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var clientset *kubernetes.Clientset

var globalConfig struct {
	Partition   string
	RouteDomain string
	VIPCIDR     string
	F5Host      string
	F5User      string
	F5Pass      string
	IbHost      string
	IbUser      string
	IbPass      string
	IbActive    bool
}

var f5State struct {
	Virtuals []bigip.VirtualServer `json:"virtuals",omitempty`
	Pools    []bigip.Pool          `json:"pools",omitempty`
	Monitors []bigip.Monitor       `json:"monitors",omitempty`
	Nodes    []bigip.Node          `json:"nodes",omitempty`
}

// Initialize the connection to Kubernetes

func initKubernetes() error {

	// Try initializing using the credentials available to a pod in Kubernetes

	config, err := rest.InClusterConfig()
	if err == nil {
		log.Debug("Connected using in-pod credentials")
		clientset, err = kubernetes.NewForConfig(config)
		return err
	}

	// That didn't work, try initializing using $HOME/.kube/config

	var home string
	if home = os.Getenv("HOME"); home == "" {
		return fmt.Errorf("HOME environment variable must be set")
	}

	kubeconfigFile := flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "absolute path to the kubeconfig file")
	flag.Parse()
	config, err = clientcmd.BuildConfigFromFlags("", *kubeconfigFile)
	if err == nil {
		clientset, err = kubernetes.NewForConfig(config)
		return err
	}

	// That didn't work, return with whatever error fell through to here

	return err
}

func f5VirtualServerName(vs KsVirtualServer) string {

	portString := strconv.FormatInt(int64(vs.Port), 10)

	vsName := "ingress_" + vs.Namespace + "_" + vs.Name + "_" + portString

	return vsName
}

func f5VSRedirectName(vs KsVirtualServer) string {

	portString := strconv.FormatInt(int64(80), 10)

	vsName := "ingress_" + vs.Namespace + "_" + vs.Name + "_" + portString

	return vsName
}

func f5PoolName(vs KsVirtualServer) string {

	pName := "ingress_" + vs.Namespace + "_" + vs.Name

	return pName
}

func f5PoolMemberName(vs KsVirtualServer, memberIndex int) string {

	portString := strconv.FormatInt(int64(vs.Members[memberIndex].Port), 10)

	mbrName := vs.Namespace + "_" + vs.Members[memberIndex].Name + ":" + portString

	return mbrName
}

func f5MonitorName(vs KsVirtualServer) string {

	mName := "ingress_" + vs.Namespace + "_" + vs.Name + "_" + vs.Monitor.Type

	return mName
}

func f5NodeName(vs KsVirtualServer, memberIndex int) string {

	nName := vs.Namespace + "_" + vs.Members[memberIndex].Name

	return nName
}

var f5 *bigip.BigIP

const f5Description = "Managed by Kubernetes. Please do not make manual changes."

var f5Metadata = bigip.Metadata{
	Name:    "f5-ingress-ctlr-managed",
	Value:   "true",
	Persist: "true",
}

var ibAddrs []ibAddr

type ibAddr struct {
	Ref  string // Infoblox reference
	Name string
	IP   string
}

type ibHosts struct {
	IPAddr  string   `json:"ip_address"`
	Names   []string `json:"names"`
	Objects []string `json:"objects"`
	View    string   `json:"network_view"`
	Types   []string `json:"types"`
}

type ibV4Addr struct {
	Host     string `json:"host"`
	IPV4Addr string `json:"ipv4addr"`
}

type ibHostRecord struct {
	IPAddrs []ibV4Addr `json:"ipv4addrs"`
	Name    string     `json:"name"`
	View    string     `json:"view"`
}

func ibRefreshState() error {

	if globalConfig.VIPCIDR == "" || globalConfig.IbHost == "" || globalConfig.IbUser == "" || globalConfig.IbPass == "" {
		return nil
	}

	u := &url.URL{
		Scheme:   "https",
		Host:     globalConfig.IbHost,
		Path:     "/wapi/v2.6/ipv4address",
		RawQuery: "network=" + globalConfig.VIPCIDR + "&_return_fields%2B=extattrs&*F5-IPAM=true",
	}

	log.WithFields(log.Fields{
		"thread": "Infoblox",
	}).Info("Refreshing the local state cache")

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(globalConfig.IbUser, globalConfig.IbPass)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Parse any IP addresses found, if any, into the IBAddrs structure

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 && resp.StatusCode > 299 {
		return fmt.Errorf("Status code was not 2xx, but %d", resp.StatusCode)
	}

	var data []ibHosts
	err = json.Unmarshal(body, &data)
	if err != nil {
		return err
	}

	globalConfig.IbActive = true

	ibAddrs = []ibAddr{}

	for _, ibh := range data {
		iba := ibAddr{}
		if len(ibh.Names) == 0 || len(ibh.Names) == 0 || len(ibh.Types) == 0 {
			log.WithFields(log.Fields{
				"ip":      ibh.IPAddr,
				"names":   ibh.Names,
				"objects": ibh.Objects,
				"thread":  "Infoblox",
				"types":   ibh.Types,
				"view":    ibh.View,
			}).Error("One of names/objects/types are empty for an Infoblox IP address record, skipping")
			continue
		}
		if len(ibh.Names) > 1 || len(ibh.Objects) > 1 || len(ibh.Types) > 1 {
			log.WithFields(log.Fields{
				"ip":      ibh.IPAddr,
				"names":   ibh.Names,
				"objects": ibh.Objects,
				"thread":  "Infoblox",
				"types":   ibh.Types,
				"view":    ibh.View,
			}).Error("Multiple names/objects/types exist for an Infoblox IP address record, skipping")
			continue
		}
		if ibh.Types[0] != "HOST" {
			log.WithFields(log.Fields{
				"ip":      ibh.IPAddr,
				"names":   ibh.Names,
				"objects": ibh.Objects,
				"thread":  "Infoblox",
				"types":   ibh.Types,
				"view":    ibh.View,
			}).Debug("This is not a host record, skipping")
			continue
		}
		iba.Ref = ibh.Objects[0]
		iba.Name = ibh.Names[0]
		iba.IP = ibh.IPAddr

		log.WithFields(log.Fields{
			"ip":     iba.IP,
			"name":   iba.Name,
			"ref":    iba.Ref,
			"thread": "Infoblox",
		}).Debug("Adding a host from the Infoblox to the state cache")

		ibAddrs = append(ibAddrs, iba)
	}
	return nil
}

func ibCreateHost(name string) (string, error) {

	if !globalConfig.IbActive {
		return "", nil
	}

	for _, iba := range ibAddrs {
		if iba.Name == name {
			return iba.IP, nil
		}
	}

	u := &url.URL{
		Scheme: "https",
		Host:   globalConfig.IbHost,
		Path:   "/wapi/v2.6/record:host",
	}

	log.WithFields(log.Fields{
		"name":   name,
		"subnet": globalConfig.VIPCIDR,
		"thread": "Infoblox",
	}).Info("Creating a host record on the Infoblox")

	// The JSON body is simple enough that we just generate here, rather than build a structure...

	jsonString := "{ \"name\":\"" + name + "\", \"ipv4addrs\":[{\"ipv4addr\":\"func:nextavailableip:" + globalConfig.VIPCIDR + "\"}], \"use_ttl\":true, \"ttl\":60, \"extattrs\":{\"F5-IPAM\":{\"value\":\"true\"}}}"

	req, err := http.NewRequest("POST", u.String(), strings.NewReader(jsonString))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(globalConfig.IbUser, globalConfig.IbPass)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return "", err
	}

	if resp.StatusCode < 200 && resp.StatusCode > 299 {
		resp.Body.Close()
		return "", fmt.Errorf("Status code was not 2xx, but %d", resp.StatusCode)
	}

	hostRef := string(body[1 : len(body)-1])

	u = &url.URL{
		Scheme: "https",
		Host:   globalConfig.IbHost,
		Path:   "/wapi/v2.6/" + hostRef,
	}

	log.WithFields(log.Fields{
		"ibref":  hostRef,
		"name":   name,
		"thread": "Infoblox",
	}).Debug("Retreiving the IP address details based on the reference received")

	// The JSON body is simple enough that we just generate here, rather than build a structure...

	req, err = http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(globalConfig.IbUser, globalConfig.IbPass)

	client = &http.Client{Transport: tr}

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode < 200 && resp.StatusCode > 299 {
		return "", fmt.Errorf("Status code was not 2xx, but %d", resp.StatusCode)
	}

	var ibh ibHostRecord
	err = json.Unmarshal(body, &ibh)
	if err != nil {
		return "", err
	}

	if len(ibh.IPAddrs) == 0 {
		return "", fmt.Errorf("No IP address was found in the response")
	}

	if len(ibh.IPAddrs) > 1 {
		return "", fmt.Errorf("Too many IP addresses were found in the response")
	}

	iba := ibAddr{
		Ref:  hostRef,
		Name: ibh.Name,
		IP:   ibh.IPAddrs[0].IPV4Addr,
	}

	log.WithFields(log.Fields{
		"ip":     iba.IP,
		"name":   iba.Name,
		"ref":    iba.Ref,
		"thread": "Infoblox",
	}).Debug("Adding the host to the state cache")

	ibAddrs = append(ibAddrs, iba)

	return iba.IP, nil
}

func ibReleaseIP(ipAddr string) error {

	if !globalConfig.IbActive {
		return nil
	}

	found := false
	var idx int
	var ip ibAddr
	for idx, ip = range ibAddrs {
		if ipAddr == ip.IP {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("The IP address %s was not found in the Infoblox state cache", ipAddr)
	}

	u := &url.URL{
		Scheme: "https",
		Host:   globalConfig.IbHost,
		Path:   "/wapi/v2.6/" + ip.Ref,
	}

	log.WithFields(log.Fields{
		"hostname": ip.Name,
		"ibref":    ip.Ref,
		"ip":       ip.IP,
		"thread":   "Infoblox",
	}).Info("Removing the host record from the Infoblox")

	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth(globalConfig.IbUser, globalConfig.IbPass)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	resp.Body.Close()

	log.WithFields(log.Fields{
		"hostname": ip.Name,
		"ibref":    ip.Ref,
		"ip":       ip.IP,
		"thread":   "Infoblox",
	}).Debug("Removing the host record from the Infoblox state cache")

	ibAddrs = append(ibAddrs[:idx], ibAddrs[idx+1:]...)
	return nil
}

func addNode(vs KsVirtualServer, memberIdx int) error {

	nodeName := f5NodeName(vs, memberIdx)
	nodeFullPath := "/" + globalConfig.Partition + "/" + nodeName

	for _, node := range f5State.Nodes {
		if nodeName == node.Name {
			return nil // Nodes don't change, just return if present
		}
	}

	nodeConfig := &bigip.Node{
		Description: f5Description,
		Address:     vs.Members[memberIdx].IP,
		Name:        nodeName,
		Partition:   globalConfig.Partition,
	}
	nodeConfig.Metadata = append([]bigip.Metadata{}, f5Metadata)

	log.WithFields(log.Fields{
		"node":   nodeName,
		"thread": "F5",
	}).Info("Adding a node to the F5")
	configJson, _ := json.Marshal(nodeConfig)
	log.WithFields(log.Fields{
		"config": string(configJson),
		"thread": "F5",
	}).Debug("")

	if err := f5.AddNode(nodeConfig); err != nil {
		return err
	}

	node, err := f5.GetNode(nodeFullPath)
	if err != nil {
		return err
	}

	if node == nil {
		return fmt.Errorf("f5.GetNode returned nil")
	}

	log.WithFields(log.Fields{
		"node":   nodeName,
		"thread": "F5",
	}).Debug("Adding a node to the state cache")
	f5State.Nodes = append(f5State.Nodes, *node)

	return nil
}

func addPoolMember(vs KsVirtualServer, memberIdx int) error {

	memberName := f5PoolMemberName(vs, memberIdx)
	memberFullPath := "/" + globalConfig.Partition + "/" + memberName
	poolName := f5PoolName(vs)
	poolFullPath := "/" + globalConfig.Partition + "/" + poolName

	poolFound := false
	for _, pool := range f5State.Pools {
		if poolName == pool.Name {
			poolFound = true
			if pool.Members != nil {
				for _, poolMember := range *pool.Members {
					if memberName == poolMember.Name {
						return nil
					}
				}
			}
		}
	}

	if !poolFound {
		return nil // Don't try anything if the parent pool is not configured
	}

	memberConfig := &bigip.PoolMember{
		Description: f5Description,
		Name:        memberName,
		Partition:   globalConfig.Partition,
	}
	memberConfig.Metadata = append([]bigip.Metadata{}, f5Metadata)

	log.WithFields(log.Fields{
		"member": memberName,
		"pool":   poolName,
		"thread": "F5",
	}).Info("Adding a pool member to the F5")
	configJson, _ := json.Marshal(memberConfig)
	log.WithFields(log.Fields{
		"config": string(configJson),
		"thread": "F5",
	}).Debug("")

	if err := f5.CreatePoolMember(poolFullPath, memberConfig); err != nil {
		return err
	}

	member, err := f5.GetPoolMember(poolFullPath, memberFullPath)
	if err != nil {
		return err
	}

	if member == nil {
		return fmt.Errorf("f5.GetPoolMember returned nil")
	}

	log.WithFields(log.Fields{
		"member": memberName,
		"thread": "F5",
	}).Debug("Adding a member to the state cache")
	for idx, pool := range f5State.Pools {
		if poolName == pool.Name {
			newPoolMembers := []bigip.PoolMember{}
			if pool.Members != nil {
				newPoolMembers = append(newPoolMembers, *pool.Members...)
			}
			newPoolMembers = append(newPoolMembers, *member)
			f5State.Pools[idx].Members = &newPoolMembers
		}
	}

	return nil
}

func addPreField(addOldValue bool, field string, value string) string {

	str := field + ":"
	if addOldValue {
		str = str + value + ":to:"
	}
	return str
}

func addPreFieldInt(addOldValue bool, field string, value int) string {

	str := field + ":"
	if addOldValue {
		str = str + strconv.FormatInt(int64(value), 10) + ":to:"
	}
	return str
}

func addPostField(oldArray []string, strSoFar string, value string) []string {

	str := strSoFar + value
	newArray := append(oldArray, str)
	return newArray
}

func addPostFieldInt(oldArray []string, strSoFar string, value int) []string {

	str := strSoFar + strconv.FormatInt(int64(value), 10)
	newArray := append(oldArray, str)
	return newArray
}

func addOrChangeMonitor(vs KsVirtualServer) error {

	monitorName := f5MonitorName(vs)
	monitorFullPath := "/" + globalConfig.Partition + "/" + monitorName
	var monitorConfig bigip.Monitor

	fieldsChanged := []string{}
	existingFound := false
	for _, monitor := range f5State.Monitors {
		if monitorName == monitor.Name {
			monitorConfig.Description = monitor.Description
			monitorConfig.Interval = monitor.Interval
			monitorConfig.ReceiveString = monitor.ReceiveString
			monitorConfig.SendString = monitor.SendString
			monitorConfig.Timeout = monitor.Timeout
			existingFound = true
			break
		}
	}

	if !existingFound {
		monitorConfig.FullPath = monitorFullPath
		monitorConfig.Metadata = append([]bigip.Metadata{}, f5Metadata)
		monitorConfig.Name = monitorName
		monitorConfig.Partition = globalConfig.Partition
	}

	updated := false

	if f5Description != monitorConfig.Description {
		monitorConfig.Description = f5Description
		fieldsChanged = append(fieldsChanged, "Description:reset")
		updated = true
	}

	if vs.Monitor.Interval != monitorConfig.Interval {
		if !(vs.Monitor.Interval == 0 && monitorConfig.Interval == 5) {
			tmpStr := addPreFieldInt(existingFound, "Interval", monitorConfig.Interval)
			monitorConfig.Interval = vs.Monitor.Interval
			if vs.Monitor.Interval == 0 {
				monitorConfig.Interval = 5
			}
			fieldsChanged = addPostFieldInt(fieldsChanged, tmpStr, monitorConfig.Interval)
			updated = true
		}
	}

	if vs.Monitor.Receive != monitorConfig.ReceiveString {
		tmpStr := addPreField(existingFound, "ReceiveString", monitorConfig.ReceiveString)
		monitorConfig.ReceiveString = vs.Monitor.Receive
		fieldsChanged = addPostField(fieldsChanged, tmpStr, monitorConfig.ReceiveString)
		updated = true
	}

	tmp := strings.Replace(vs.Monitor.Send, "\r", "\\r", -1)
	escapedSend := strings.Replace(tmp, "\n", "\\n", -1)
	if escapedSend != monitorConfig.SendString {
		if !((vs.Monitor.Send == "" || vs.Monitor.Send == "GET /\r\n") && monitorConfig.SendString == "GET /\\r\\n") {
			tmpStr := addPreField(existingFound, "SendString", monitorConfig.SendString)
			monitorConfig.SendString = vs.Monitor.Send
			if vs.Monitor.Send == "" {
				monitorConfig.SendString = "GET /\\r\\n"
			}
			fieldsChanged = addPostField(fieldsChanged, tmpStr, monitorConfig.SendString)
			updated = true
		}
	}

	if vs.Monitor.Timeout != monitorConfig.Timeout {
		if !(vs.Monitor.Timeout == 0 && monitorConfig.Timeout == 16) {
			tmpStr := addPreFieldInt(existingFound, "Timeout", monitorConfig.Timeout)
			monitorConfig.Timeout = vs.Monitor.Timeout
			if vs.Monitor.Timeout == 0 {
				monitorConfig.Timeout = 16
			}
			fieldsChanged = addPostFieldInt(fieldsChanged, tmpStr, monitorConfig.Timeout)
			updated = true
		}
	}

	if existingFound && !updated {
		return nil
	}

	if existingFound {
		log.WithFields(log.Fields{
			"changed": fieldsChanged,
			"monitor": monitorFullPath,
			"thread":  "F5",
			"type":    vs.Monitor.Type,
		}).Info("Updating a monitor on the F5")
		configJson, _ := json.Marshal(monitorConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
			"type":   vs.Monitor.Type,
		}).Debug("")
		err := f5.PatchMonitor(monitorFullPath, vs.Monitor.Type, &monitorConfig)
		if err != nil {
			return err
		}
	} else {
		log.WithFields(log.Fields{
			"added":   fieldsChanged,
			"monitor": monitorFullPath,
			"thread":  "F5",
			"type":    vs.Monitor.Type,
		}).Info("Adding a monitor to the F5")
		configJson, _ := json.Marshal(monitorConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
		}).Debug("")

		if err := f5.AddMonitor(&monitorConfig, vs.Monitor.Type); err != nil {
			return err
		}
	}

	monitor, err := f5.GetMonitor(monitorFullPath, vs.Monitor.Type)
	if err != nil {
		return err
	}

	if monitor == nil {
		return fmt.Errorf("f5.GetMonitor returned nil")
	}

	// For reasons that aren't clear, the monitor.MonitorType field is not set correctly
	// after creating it (but it is there later when you pull a full list of monitors)
	//
	// Since I know it here, I'm forcefully setting it here so everything downstream
	// has it.

	monitor.MonitorType = vs.Monitor.Type

	if existingFound {
		log.WithFields(log.Fields{
			"monitor": monitor.FullPath,
			"thread":  "F5",
			"type":    monitor.MonitorType,
		}).Debug("Updating a monitor in the state cache")
		for idx, f5monitor := range f5State.Monitors {
			if monitorName == f5monitor.Name {
				f5State.Monitors[idx] = *monitor
				break
			}
		}
	} else {
		log.WithFields(log.Fields{
			"monitor": monitor.FullPath,
			"thread":  "F5",
			"type":    monitor.MonitorType,
		}).Debug("Adding a monitor to the state cache")
		f5State.Monitors = append(f5State.Monitors, *monitor)
	}

	return nil
}

func addOrChangePool(vs KsVirtualServer) error {

	poolName := f5PoolName(vs)
	poolFullPath := "/" + globalConfig.Partition + "/" + poolName
	var poolConfig bigip.Pool

	fieldsChanged := []string{}
	existingFound := false
	for _, pool := range f5State.Pools {
		if poolName == pool.Name {
			poolConfig.Description = pool.Description
			poolConfig.LoadBalancingMode = pool.LoadBalancingMode
			poolConfig.Monitor = strings.TrimRight(pool.Monitor, " ")
			existingFound = true
			break
		}
	}

	if !existingFound {
		poolConfig.FullPath = poolFullPath
		poolConfig.Metadata = append([]bigip.Metadata{}, f5Metadata)
		poolConfig.Name = poolName
		poolConfig.Partition = globalConfig.Partition
	}

	updated := false

	if f5Description != poolConfig.Description {
		poolConfig.Description = f5Description
		updated = true
	}

	if vs.LBMode != poolConfig.LoadBalancingMode {
		if !(vs.LBMode == "" && poolConfig.LoadBalancingMode == "round-robin") {
			tmpStr := addPreField(existingFound, "LoadBalancingMode", poolConfig.LoadBalancingMode)
			poolConfig.LoadBalancingMode = vs.LBMode
			fieldsChanged = addPostField(fieldsChanged, tmpStr, poolConfig.LoadBalancingMode)
			updated = true
		}
	}

	monitorName := f5MonitorName(vs)
	monitorFullPath := ""
	for _, monitor := range f5State.Monitors {
		if monitorName == monitor.Name {
			monitorFullPath = monitor.FullPath
			break
		}
	}

	if monitorFullPath != poolConfig.Monitor {
		tmpStr := addPreField(existingFound, "Monitor", poolConfig.Monitor)
		poolConfig.Monitor = monitorFullPath
		fieldsChanged = addPostField(fieldsChanged, tmpStr, poolConfig.Monitor)
		updated = true
	}

	if existingFound && !updated {
		return nil
	}

	if existingFound {
		log.WithFields(log.Fields{
			"changed": fieldsChanged,
			"pool":    poolName,
			"thread":  "F5",
		}).Info("Updating a pool on the F5")
		configJson, _ := json.Marshal(poolConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
		}).Debug("")
		err := f5.ModifyPool(poolFullPath, &poolConfig)
		if err != nil {
			return err
		}
	} else {
		log.WithFields(log.Fields{
			"added":  fieldsChanged,
			"pool":   poolName,
			"thread": "F5",
		}).Info("Adding a pool to the F5")
		configJson, _ := json.Marshal(poolConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
		}).Debug("")

		if err := f5.AddPool(&poolConfig); err != nil {
			return err
		}
	}

	pool, err := f5.GetPool(poolFullPath)
	if err != nil {
		return err
	}

	if pool == nil {
		return fmt.Errorf("f5.GetPool returned nil")
	}

	poolMembers, err := f5.PoolMembers(pool.FullPath)
	if err != nil {
		return err
	}

	if poolMembers == nil {
		return fmt.Errorf("f5.PoolMembers returned nil")
	}

	pool.Members = &poolMembers.PoolMembers

	if existingFound {
		log.WithFields(log.Fields{
			"pool":   poolName,
			"thread": "F5",
		}).Debug("Updating a pool in the state cache")
		for idx, f5pool := range f5State.Pools {
			if poolName == f5pool.Name {
				f5State.Pools[idx] = *pool
				break
			}
		}
	} else {
		log.WithFields(log.Fields{
			"pool":   poolName,
			"thread": "F5",
		}).Debug("Adding a pool to the state cache")
		f5State.Pools = append(f5State.Pools, *pool)
	}

	return nil
}

func addOrChangeVirtualServer(vs KsVirtualServer) error {

	vsName := f5VirtualServerName(vs)
	vsFullPath := "/" + globalConfig.Partition + "/" + vsName
	var vsConfig bigip.VirtualServer

	fieldsChanged := []string{}
	existingFound := false
	for _, vs := range f5State.Virtuals {
		if vsName == vs.Name {
			vsConfig = vs
			existingFound = true
			break
		}
	}

	if !existingFound {
		vsConfig.FullPath = vsFullPath
		vsConfig.Metadata = append([]bigip.Metadata{}, f5Metadata)
		vsConfig.Name = vsName
		vsConfig.Partition = globalConfig.Partition
	}

	updated := false

	if f5Description != vsConfig.Description {
		vsConfig.Description = f5Description
		updated = true
	}

	ipDest := ""

	if vs.IbEnabled {
		if vs.IbDynamicIP {
			if !existingFound {
				hostname := vs.IbHostname
				if hostname != "" {
					var err error
					ipDest, err = ibCreateHost(hostname)
					if err != nil {
						log.Info("Unable to allocate an IP from the Infoblox, will try again later")
						log.Error(err.Error())
					}
				} else {
					log.Info("We cannot create a dynamic IP address without a hostname")
				}
			} else {
				splitString := strings.Split(vsConfig.Destination, "/")
				secondSplitString := strings.Split(splitString[2], "%")
				ipDest = secondSplitString[0]
			}
		} else {
			ipDest = vs.IP
		}
	} else {
		ipDest = vs.IP
	}

	if ipDest == "" {
		ipDest = "0.0.0.0"
	}

	vsDestination := fmt.Sprintf("/%s/%s%%%s:%d", globalConfig.Partition, ipDest, globalConfig.RouteDomain, vs.Port)

	if vsDestination != vsConfig.Destination {
		tmpStr := addPreField(existingFound, "Destination", vsConfig.Destination)
		vsConfig.Destination = vsDestination
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.Destination)
		updated = true
	}

	if "tcp" != vsConfig.IPProtocol {
		tmpStr := addPreField(existingFound, "IPProtocol", vsConfig.IPProtocol)
		vsConfig.IPProtocol = "tcp"
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.IPProtocol)
		updated = true
	}

	if "255.255.255.255" != vsConfig.Mask {
		tmpStr := addPreField(existingFound, "Mask", vsConfig.Mask)
		vsConfig.Mask = "255.255.255.255"
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.Mask)
		updated = true
	}

	sourceStr := fmt.Sprintf("0.0.0.0%%%s/0", globalConfig.RouteDomain)
	if sourceStr != vsConfig.Source && "0.0.0.0/0" != vsConfig.Source {
		tmpStr := addPreField(existingFound, "Source", vsConfig.Source)
		vsConfig.Source = sourceStr
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.Source)
		updated = true
	}

	if "automap" != vsConfig.SourceAddressTranslation.Type {
		tmpStr := addPreField(existingFound, "SourceAddressTranslation.Type", vsConfig.SourceAddressTranslation.Type)
		vsConfig.SourceAddressTranslation.Type = "automap"
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.SourceAddressTranslation.Type)
		updated = true
	}

	if vs.DefPersist == "" && len(vsConfig.Persistence) > 0 {
		log.Debug("Default persistence updated (removed)")
		vsConfig.Persistence = []bigip.Persistence{}
		updated = true
	}

	if vs.DefPersist != "" && len(vsConfig.Persistence) > 1 {
		log.Debug("Default persistence updated (too many)")
		updated = true
	}

	if vs.DefPersist != "" {
		splitString := strings.Split(vs.DefPersist, "/")
		found := false
		for _, p := range vsConfig.Persistence {
			if p.Name == splitString[2] && p.Partition == splitString[1] && p.Default == "yes" {
				found = true
			}
		}
		if !found {
			log.Debug("Updated default persistence (added it)")
			updated = true
		}
		defPersist := bigip.Persistence{
			Name:      splitString[2],
			Partition: splitString[1],
			Default:   "yes",
		}
		vsConfig.Persistence = append([]bigip.Persistence{}, defPersist)
	}

	if vs.FBPersist != vsConfig.FallbackPersistence {
		log.Debug("Fallback persistence updated")
		vsConfig.FallbackPersistence = vs.FBPersist
		updated = true
	}

	newProfile := []bigip.Profile{}
	profileUpdated := false

	found := false
	for _, p := range vsConfig.Profiles {
		if p.Name == "http" && p.Partition == "Common" && p.Context == "all" {
			newProfile = append(newProfile, p)
			found = true
		}
	}
	if !found {
		httpProfile := bigip.Profile{
			Context:   "all",
			Name:      "http",
			Partition: "Common",
		}
		newProfile = append(newProfile, httpProfile)
		profileUpdated = true
	}

	found = false
	for _, p := range vsConfig.Profiles {
		if p.Name == "tcp" && p.Partition == "Common" && p.Context == "all" {
			newProfile = append(newProfile, p)
			found = true
		}
	}
	if !found {
		tcpProfile := bigip.Profile{
			Context:   "all",
			Name:      "tcp",
			Partition: "Common",
		}
		newProfile = append(newProfile, tcpProfile)
		profileUpdated = true
	}
	if vs.ClientSSL == "" {
		for _, p := range vsConfig.Profiles {
			if p.Context == "clientside" {
				profileUpdated = true
			}
		}
	}

	if vs.ClientSSL != "" {
		splitString := strings.Split(vs.ClientSSL, "/")

		found = false
		for _, p := range vsConfig.Profiles {
			if p.Name == splitString[2] && p.Partition == splitString[1] && p.Context == "clientside" {
				newProfile = append(newProfile, p)
				found = true
			}
		}
		if !found {
			clientSSLProfile := bigip.Profile{
				Context:   "clientside",
				Name:      splitString[2],
				Partition: splitString[1],
			}
			newProfile = append(newProfile, clientSSLProfile)
			profileUpdated = true
		}
	}

	if vs.ServerSSL == "" {
		for _, p := range vsConfig.Profiles {
			if p.Context == "serverside" {
				profileUpdated = true
			}
		}
	}

	if vs.ServerSSL != "" {
		splitString := strings.Split(vs.ServerSSL, "/")

		found = false
		for _, p := range vsConfig.Profiles {
			if p.Name == splitString[2] && p.Partition == splitString[1] && p.Context == "serverside" {
				newProfile = append(newProfile, p)
				found = true
			}
		}
		if !found {
			serverSSLProfile := bigip.Profile{
				Context:   "serverside",
				Name:      splitString[2],
				Partition: splitString[1],
			}
			newProfile = append(newProfile, serverSSLProfile)
			profileUpdated = true
		}
	}

	if len(newProfile) != len(vsConfig.Profiles) {
		profileUpdated = true
	}

	if profileUpdated {
		log.Debug("Profiles updated")
		vsConfig.Profiles = append([]bigip.Profile{}, newProfile...)
		updated = true
	}

	rulesUpdated := false
	for _, f5Rule := range vsConfig.Rules {
		found := false
		for _, r := range vs.IRules {
			if r == f5Rule {
				found = true
			}
		}
		if !found {
			rulesUpdated = true
		}
	}

	for _, r := range vs.IRules {
		found := false
		for _, f5Rule := range vsConfig.Rules {
			if f5Rule == r {
				found = true
			}
		}
		if !found {
			rulesUpdated = true
		}
	}

	if rulesUpdated {
		log.Debug("Updating IRules")
		vsConfig.Rules = vs.IRules
	}

	poolName := f5PoolName(vs)
	poolFullPath := ""
	for _, pool := range f5State.Pools {
		if poolName == pool.Name {
			poolFullPath = pool.FullPath
			break
		}
	}

	if poolFullPath != vsConfig.Pool {
		log.Debug("Updating Pool")
		vsConfig.Pool = poolFullPath
		updated = true
	}

	if existingFound && !updated {
		return nil
	}

	if existingFound {
		log.WithFields(log.Fields{
			"changed":       fieldsChanged,
			"virtualServer": vsName,
			"thread":        "F5",
		}).Info("Updating a virtual server on the F5")
		configJson, _ := json.Marshal(vsConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
		}).Debug("")
		if err := f5.ModifyVirtualServer(vsFullPath, &vsConfig); err != nil {
			return err
		}
	} else {
		log.WithFields(log.Fields{
			"added":         fieldsChanged,
			"virtualServer": vsName,
			"thread":        "F5",
		}).Info("Adding a virtual server to the F5")
		configJson, _ := json.Marshal(vsConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
		}).Debug("")

		if err := f5.AddVirtualServer(&vsConfig); err != nil {
			return err
		}
	}

	newVs, err := f5.GetVirtualServer(vsFullPath)
	if err != nil {
		return err
	}

	if newVs == nil {
		return fmt.Errorf("f5.GetVirtualServer returned nil")
	}

	if existingFound {
		log.WithFields(log.Fields{
			"virtualServer": vsName,
			"thread":        "F5",
		}).Debug("Updating a virtual server in the state cache")
		for idx, f5vs := range f5State.Virtuals {
			if vsName == f5vs.Name {
				f5State.Virtuals[idx] = *newVs
				break
			}
		}
	} else {
		log.WithFields(log.Fields{
			"virtualServer": vsName,
			"thread":        "F5",
		}).Debug("Adding a virtual server to the state cache")
		f5State.Virtuals = append(f5State.Virtuals, *newVs)
	}

	return nil
}

func addOrChangeVSRedirect(vs KsVirtualServer) error {

	vsName := f5VSRedirectName(vs)
	vsFullPath := "/" + globalConfig.Partition + "/" + vsName
	var vsConfig bigip.VirtualServer

	fieldsChanged := []string{}
	existingFound := false
	for _, vs := range f5State.Virtuals {
		if vsName == vs.Name {
			vsConfig = vs
			existingFound = true
			break
		}
	}

	if !existingFound {
		vsConfig.FullPath = vsFullPath
		vsConfig.Metadata = append([]bigip.Metadata{}, f5Metadata)
		vsConfig.Name = vsName
		vsConfig.Partition = globalConfig.Partition
	}

	updated := false

	if f5Description != vsConfig.Description {
		vsConfig.Description = f5Description
		updated = true
	}

	ipDest := ""

	if vs.IbEnabled {
		if vs.IbDynamicIP {
			if !existingFound {
				hostname := vs.IbHostname
				if hostname != "" {
					var err error
					ipDest, err = ibCreateHost(hostname)
					if err != nil {
						log.Info("Unable to allocate an IP from the Infoblox, will try again later")
						log.Error(err.Error())
					}
				} else {
					log.Info("We cannot create a dynamic IP address without a hostname")
				}
			} else {
				splitString := strings.Split(vsConfig.Destination, "/")
				secondSplitString := strings.Split(splitString[2], "%")
				ipDest = secondSplitString[0]
			}
		} else {
			ipDest = vs.IP
		}
	} else {
		ipDest = vs.IP
	}

	if ipDest == "" {
		ipDest = "0.0.0.0"
	}

	vsDestination := fmt.Sprintf("/%s/%s%%%s:80", globalConfig.Partition, ipDest, globalConfig.RouteDomain)

	if vsDestination != vsConfig.Destination {
		tmpStr := addPreField(existingFound, "Destination", vsConfig.Destination)
		vsConfig.Destination = vsDestination
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.Destination)
		updated = true
	}

	if "tcp" != vsConfig.IPProtocol {
		tmpStr := addPreField(existingFound, "IPProtocol", vsConfig.IPProtocol)
		vsConfig.IPProtocol = "tcp"
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.IPProtocol)
		updated = true
	}

	if "255.255.255.255" != vsConfig.Mask {
		tmpStr := addPreField(existingFound, "Mask", vsConfig.Mask)
		vsConfig.Mask = "255.255.255.255"
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.Mask)
		updated = true
	}

	sourceStr := fmt.Sprintf("0.0.0.0%%%s/0", globalConfig.RouteDomain)
	if sourceStr != vsConfig.Source && "0.0.0.0/0" != vsConfig.Source {
		tmpStr := addPreField(existingFound, "Source", vsConfig.Source)
		vsConfig.Source = sourceStr
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.Source)
		updated = true
	}

	if "automap" != vsConfig.SourceAddressTranslation.Type {
		tmpStr := addPreField(existingFound, "SourceAddressTranslation.Type", vsConfig.SourceAddressTranslation.Type)
		vsConfig.SourceAddressTranslation.Type = "automap"
		fieldsChanged = addPostField(fieldsChanged, tmpStr, vsConfig.SourceAddressTranslation.Type)
		updated = true
	}

	newProfile := []bigip.Profile{}
	profileUpdated := false

	found := false
	for _, p := range vsConfig.Profiles {
		if p.Name == "http" && p.Partition == "Common" && p.Context == "all" {
			newProfile = append(newProfile, p)
			found = true
		}
	}
	if !found {
		httpProfile := bigip.Profile{
			Context:   "all",
			Name:      "http",
			Partition: "Common",
		}
		newProfile = append(newProfile, httpProfile)
		profileUpdated = true
	}

	found = false
	for _, p := range vsConfig.Profiles {
		if p.Name == "tcp" && p.Partition == "Common" && p.Context == "all" {
			newProfile = append(newProfile, p)
			found = true
		}
	}
	if !found {
		tcpProfile := bigip.Profile{
			Context:   "all",
			Name:      "tcp",
			Partition: "Common",
		}
		newProfile = append(newProfile, tcpProfile)
		profileUpdated = true
	}

	if len(newProfile) != len(vsConfig.Profiles) {
		profileUpdated = true
	}

	if profileUpdated {
		log.Debug("Profiles updated")
		vsConfig.Profiles = append([]bigip.Profile{}, newProfile...)
		updated = true
	}

	rulesUpdated := true
	if len(vsConfig.Rules) == 1 && vsConfig.Rules[0] == "/Common/_sys_https_redirect" {
		rulesUpdated = false
	}
	if rulesUpdated {
		log.Debug("Updating IRules")
		vsConfig.Rules = []string{"/Common/_sys_https_redirect"}
	}

	poolName := f5PoolName(vs)
	poolFullPath := ""
	for _, pool := range f5State.Pools {
		if poolName == pool.Name {
			poolFullPath = pool.FullPath
			break
		}
	}

	if poolFullPath != vsConfig.Pool {
		log.Debug("Updating Pool")
		vsConfig.Pool = poolFullPath
		updated = true
	}

	if existingFound && !updated {
		return nil
	}

	if existingFound {
		log.WithFields(log.Fields{
			"changed":       fieldsChanged,
			"virtualServer": vsName,
			"thread":        "F5",
		}).Info("Updating a virtual server redirect on the F5")
		configJson, _ := json.Marshal(vsConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
		}).Debug("")
		if err := f5.ModifyVirtualServer(vsFullPath, &vsConfig); err != nil {
			return err
		}
	} else {
		log.WithFields(log.Fields{
			"added":         fieldsChanged,
			"virtualServer": vsName,
			"thread":        "F5",
		}).Info("Adding a virtual server redirect to the F5")
		configJson, _ := json.Marshal(vsConfig)
		log.WithFields(log.Fields{
			"config": string(configJson),
			"thread": "F5",
		}).Debug("")

		if err := f5.AddVirtualServer(&vsConfig); err != nil {
			return err
		}
	}

	newVs, err := f5.GetVirtualServer(vsFullPath)
	if err != nil {
		return err
	}

	if newVs == nil {
		return fmt.Errorf("f5.GetVirtualServer returned nil")
	}

	if existingFound {
		log.WithFields(log.Fields{
			"virtualServer": vsName,
			"thread":        "F5",
		}).Debug("Updating a virtual server redirect in the state cache")
		for idx, f5vs := range f5State.Virtuals {
			if vsName == f5vs.Name {
				f5State.Virtuals[idx] = *newVs
				break
			}
		}
	} else {
		log.WithFields(log.Fields{
			"virtualServer": vsName,
			"thread":        "F5",
		}).Debug("Adding a virtual server redirect to the state cache")
		f5State.Virtuals = append(f5State.Virtuals, *newVs)
	}

	return nil
}

/* deleteMonitor

Takes a bigip.Monitor structure, and deletes that monitor off
the F5. If successful, it is removed from the f5State.Monitors
cache.

Prior to deleting the monitor, all pools in our partition are
scanned to see if there's a reference to the monitor, and if so,
the monitor reference is removed from the pool.

If anything went wrong, the error is returned to the caller to handle.
*/

func deleteMonitor(monitor bigip.Monitor) error {

	// Walk the array of pools

	for _, pool := range f5State.Pools {

		if pool.Monitor == monitor.FullPath {

			log.WithFields(log.Fields{
				"monitor": monitor.FullPath,
				"pool":    pool.Name,
				"thread":  "F5",
			}).Info("Removing a monitor reference ****TODO****")
		}
	}

	// Call the F5 to delete the monitor

	log.WithFields(log.Fields{
		"monitor": monitor.FullPath,
		"thread":  "F5",
		"type":    monitor.MonitorType,
	}).Info("Removing a monitor from the F5")

	if err := f5.DeleteMonitor(monitor.FullPath, monitor.MonitorType); err != nil {
		return err
	}

	// Remove it from the array of monitors in the F5 state cache

	log.WithFields(log.Fields{
		"monitor": monitor.FullPath,
		"thread":  "F5",
	}).Debug("Removing a monitor from the state cache")

	for idx, stateMonitor := range f5State.Monitors {
		if monitor.FullPath == stateMonitor.FullPath {
			f5State.Monitors = append(f5State.Monitors[:idx], f5State.Monitors[idx+1:]...)
			break
		}
	}

	return nil
}

/* deleteNode

Takes a bigip.Node structure, and deletes that node off the F5.
If successful, it is removed from the f5State.Nodes cache.

Prior to deleting the node, all pool members in our partition are scanned
to see if there's an association with the node, and if so, the pool member
is removed from the pool before deleting the node.

If anything went wrong, the error is returned to the caller to handle.
*/

func deleteNode(node bigip.Node) error {

	// Walk the array of pools

	for idx, pool := range f5State.Pools {

		if pool.Members != nil {

			// If there are pool members in the pool, walk that array
			// to see if any match the node we're looking to remove

			for _, poolMember := range *pool.Members {

				// The node name in a pool is <node>:<port>, strip
				// off the port.  We skip entries that don't match
				// this pattern.

				splitString := strings.Split(poolMember.FullPath, ":")
				if len(splitString) < 2 {
					log.WithFields(log.Fields{
						"member": poolMember.FullPath,
						"pool":   pool.FullPath,
						"thread": "F5",
					}).Debug("A pool member isn't in <node>:<port> format. Skipping it")
					continue
				}

				if splitString[0] == node.FullPath {
					poolMemberConfig := &bigip.PoolMember{
						FullPath:  poolMember.FullPath,
						Name:      poolMember.Name,
						Partition: globalConfig.Partition,
					}
					log.WithFields(log.Fields{
						"member": poolMember.Name,
						"pool":   pool.FullPath,
						"thread": "F5",
					}).Info("Removing a pool member from the F5")
					if err := f5.RemovePoolMember(pool.FullPath, poolMemberConfig); err != nil {
						return err
					}

					log.WithFields(log.Fields{
						"member": poolMember.Name,
						"pool":   pool.FullPath,
						"thread": "F5",
					}).Debug("Removing a pool member from the state cache")
					newPoolMembers := []bigip.PoolMember{}
					for _, pm := range *pool.Members {
						if pm.FullPath != poolMember.FullPath {
							newPoolMembers = append(newPoolMembers, pm)
						}
					}

					f5State.Pools[idx].Members = &newPoolMembers
					break // Don't scan the remaining pool members
				}
			}
		}
	}

	// Call the F5 to delete the node

	log.WithFields(log.Fields{
		"node":   node.Name,
		"thread": "F5",
	}).Info("Removing a node from the F5")

	if err := f5.DeleteNode(node.FullPath); err != nil {
		return err
	}

	// Remove it from the array of nodes in the F5 state cache

	log.WithFields(log.Fields{
		"node":   node.FullPath,
		"thread": "F5",
	}).Debug("Removing a node from the state cache")

	for idx, stateNode := range f5State.Nodes {
		if node.FullPath == stateNode.FullPath {
			f5State.Nodes = append(f5State.Nodes[:idx], f5State.Nodes[idx+1:]...)
			break
		}
	}

	return nil
}

/* deletePool

Takes a bigip.Pool structure, and deletes that pool off the F5.
If successful, it is removed from the f5State.Pools cache.

Prior to deleting the pool, all vrtual servers in our partition
are scanned to see if there's an association with the pool, and
if so, the reference to the pool is removed from the virtual
server before deleting the pool.  *** THIS IS A FUTURE TODO ***

If anything went wrong, the error is returned to the caller to handle.
*/

func deletePool(pool bigip.Pool) error {

	// Walk the array of virtual servers

	for _, vs := range f5State.Virtuals {

		// If a reference to the pool is found in a virtual
		// server, modify the virtual server to remove the reference

		if vs.Pool == pool.FullPath {

			log.WithFields(log.Fields{
				"pool":          pool.Name,
				"thread":        "F5",
				"virtualServer": vs.Name,
			}).Info("Removing a pool reference ****TODO****")
		}
	}

	// Call the F5 to delete the pool

	log.WithFields(log.Fields{
		"pool":   pool.FullPath,
		"thread": "F5",
	}).Info("Removing a pool from the F5")

	if err := f5.DeletePool(pool.FullPath); err != nil {
		return err
	}

	// Remove it from the array of pools in the F5 state cache

	log.WithFields(log.Fields{
		"pool":   pool.FullPath,
		"thread": "F5",
	}).Debug("Removing a pool from the state cache")

	for idx, statePool := range f5State.Pools {
		if pool.FullPath == statePool.FullPath {
			f5State.Pools = append(f5State.Pools[:idx], f5State.Pools[idx+1:]...)
			break
		}
	}

	return nil
}

/* deleteVirtualServer

Takes a bigip.Virtual structure, and deletes that virtual server
off the F5. If successful, it is removed from the f5State.Virtuals
cache.

If anything went wrong, the error is returned to the caller to handle.
*/

func deleteVirtualServer(vs bigip.VirtualServer) error {

	// Call the F5 to delete the virtual server

	log.WithFields(log.Fields{
		"thread":        "F5",
		"virtualServer": vs.FullPath,
	}).Info("Removing a virtual server from the F5")

	if err := f5.DeleteVirtualServer(vs.FullPath); err != nil {
		return err
	}

	// Remove it from the array of virtual servers in the F5 state cache

	log.WithFields(log.Fields{
		"thread":        "F5",
		"virtualServer": vs.FullPath,
	}).Debug("Removing a virtual server from the state cache")

	for idx, stateVS := range f5State.Virtuals {
		if vs.FullPath == stateVS.FullPath {
			f5State.Virtuals = append(f5State.Virtuals[:idx], f5State.Virtuals[idx+1:]...)
			break
		}
	}

	return nil
}

func applyF5Diffs(k8sState KubernetesState) error {

	// Step through virtual servers, adding or modifying sub-components as
	// necessary

	for _, vs := range k8sState {
		if err := addOrChangeMonitor(vs); err != nil {
			log.Error(err.Error())
		}
		if err := addOrChangePool(vs); err != nil {
			log.Error(err.Error())
		}
		for idx, _ := range vs.Members {
			if err := addNode(vs, idx); err != nil {
				log.Error(err.Error())
			}
			if err := addPoolMember(vs, idx); err != nil {
				log.Error(err.Error())
			}
		}
		if err := addOrChangeVirtualServer(vs); err != nil {
			log.Error(err.Error())
		}
		if vs.Redirect {
			if err := addOrChangeVSRedirect(vs); err != nil {
				log.Error(err.Error())
			}
		}
	}

	// Delete any virtual servers that are in the F5, but no longer in Kubernetes.

	f5Virtuals := make([]bigip.VirtualServer, len(f5State.Virtuals))
	copy(f5Virtuals, f5State.Virtuals)
	for _, f5vs := range f5Virtuals {
		found := false
		for _, vs := range k8sState {
			vsName := f5VirtualServerName(vs)
			if f5vs.Name == vsName {
				found = true
				break
			}
			if vs.Redirect {
				vsRedirectName := f5VSRedirectName(vs)
				if f5vs.Name == vsRedirectName {
					found = true
					break
				}
			}
		}
		if !found {
			if err := deleteVirtualServer(f5vs); err != nil {
				log.Error(err.Error())
			}
		}
	}

	// Delete any pools in the F5 not in Kubernetes

	f5Pools := make([]bigip.Pool, len(f5State.Pools))
	copy(f5Pools, f5State.Pools)
	for _, f5pool := range f5Pools {
		found := false
		for _, vs := range k8sState {
			poolName := f5PoolName(vs)
			if f5pool.Name == poolName {
				found = true
				break
			}
		}
		if !found {
			if err := deletePool(f5pool); err != nil {
				log.Error(err.Error())
			}
		}
	}

	// Delete monitors

	f5Monitors := make([]bigip.Monitor, len(f5State.Monitors))
	copy(f5Monitors, f5State.Monitors)
	for _, f5monitor := range f5Monitors {
		found := false
		for _, vs := range k8sState {
			monitorName := f5MonitorName(vs)
			if f5monitor.Name == monitorName {
				found = true
				break
			}
		}
		if !found {
			if err := deleteMonitor(f5monitor); err != nil {
				log.Error(err.Error())
			}
		}
	}

	// Nodes

	f5Nodes := make([]bigip.Node, len(f5State.Nodes))
	copy(f5Nodes, f5State.Nodes)
	for _, f5node := range f5Nodes {
		found := false
		for _, vs := range k8sState {
			for idx, _ := range vs.Members {
				nodeName := f5NodeName(vs, idx)
				if f5node.Name == nodeName {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			if err := deleteNode(f5node); err != nil {
				log.Error(err.Error())
			}
		}
	}

	return nil
}

func buildCurrentLTMState() error {

	log.WithFields(log.Fields{
		"thread": "F5",
	}).Info("Refreshing the local state cache")

	var err error
	f5, err = bigip.NewTokenSession(globalConfig.F5Host, globalConfig.F5User, globalConfig.F5Pass, "tmos", &bigip.ConfigOptions{})
	if err != nil {
		log.Debug("Failed to get token")
		return err
	}

	log.WithFields(log.Fields{
		"partition": globalConfig.Partition,
		"thread":    "F5",
	}).Debug("Retrieving all virtual servers in the partition")
	virtualServers, err := f5.VirtualServersForPartition(globalConfig.Partition)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"partition": globalConfig.Partition,
		"thread":    "F5",
	}).Debug("Retrieving all pools in the partition")
	pools, err := f5.PoolsForPartition(globalConfig.Partition)
	if err != nil {
		log.Debug("Failed to retrieve F5 pool information")
		return err
	}

	log.WithFields(log.Fields{
		"partition": globalConfig.Partition,
		"thread":    "F5",
	}).Debug("Retrieving all monitors from the partition")
	monitors, err := f5.MonitorsForPartition(globalConfig.Partition)
	if err != nil {
		log.Debug("Failed to retrieve F5 monitor information")
		return err
	}

	log.WithFields(log.Fields{
		"partition": globalConfig.Partition,
		"thread":    "F5",
	}).Debug("Retrieving all nodes from the partition")
	nodes, err := f5.NodesForPartition(globalConfig.Partition)
	if err != nil {
		log.Debug("Failed to retrieve F5 node information")
		return err
	}

	// Clean the virtual server list - only copy over virtual server
	// entries that are in our specified partition, and have a
	// metadata entry of "f5-ingress-ctlr-managed" set to "true"

	for _, virtualServer := range virtualServers.VirtualServers {
		if virtualServer.Partition == globalConfig.Partition {
			for _, metadata := range virtualServer.Metadata {
				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
					virtualProfiles, err := f5.VirtualServerProfiles(virtualServer.FullPath)
					if err != nil {
						log.WithFields(log.Fields{
							"error":         err.Error(),
							"thread":        "F5",
							"virtualServer": virtualServer.Name,
						}).Debug("Failed to fetch profiles")
					}
					virtualServer.Profiles = virtualProfiles.Profiles
					log.WithFields(log.Fields{
						"thread":        "F5",
						"virtualServer": virtualServer.Name,
					}).Debug("Adding a virtual server to the state cache")
					f5State.Virtuals = append(f5State.Virtuals, virtualServer)
					break
				}
			}
		}
	}

	// Same with pools

	for _, pool := range pools.Pools {
		if pool.Partition == globalConfig.Partition {
			for _, metadata := range pool.Metadata {
				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
					poolMembers, err := f5.PoolMembers(pool.FullPath)
					if err != nil {
						log.WithFields(log.Fields{
							"error":  err.Error(),
							"pool":   pool.Name,
							"thread": "F5",
						}).Debug("Failed to fetch pool members")
					} else {
						for _, pm := range poolMembers.PoolMembers {
							log.WithFields(log.Fields{
								"pool":       pool.Name,
								"poolMember": pm.Name,
								"thread":     "F5",
							}).Debug("Adding a pool member to the state cache")
						}
						pool.Members = &poolMembers.PoolMembers
					}
					log.WithFields(log.Fields{
						"pool":   pool.Name,
						"thread": "F5",
					}).Debug("Found a pool on the F5")
					f5State.Pools = append(f5State.Pools, pool)
					break
				}
			}
		}
	}

	// Same with monitors

	for _, monitor := range monitors {
		if monitor.Partition == globalConfig.Partition {

			// This is a temporary workaround, the metadata field doesn't translate
			// through from the F5 Go library, so we rely upon the Description for now

			//			for _, metadata := range monitor.Metadata {
			//				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {

			if monitor.Description == "Managed by Kubernetes. Please do not make manual changes." {
				log.WithFields(log.Fields{
					"monitor": monitor.Name,
					"thread":  "F5",
				}).Debug("Adding a monitor to the state cache")
				f5State.Monitors = append(f5State.Monitors, monitor)
				//					break
				//				}
			}
		}
	}

	// Finally, same with nodes

	for _, node := range nodes.Nodes {
		if node.Partition == globalConfig.Partition {
			for _, metadata := range node.Metadata {
				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
					log.WithFields(log.Fields{
						"node":   node.Name,
						"thread": "F5",
					}).Debug("Adding a node to the state cache")
					f5State.Nodes = append(f5State.Nodes, node)
					break
				}
			}
		}
	}

	return nil
}

type KsVSMonitorAttributes struct {
	Interval int    `json:"interval",omitempty`
	Send     string `json:"send",omitempty`
	Receive  string `json:"recv",omitempty`
	Timeout  int    `json:"timeout",omitempty`
	Type     string `json:"type",omitempty`
}

type KsVSMember struct {
	Name string `json:"name"`
	Port int32  `json:"port"`
	IP   string `json:"ip"`
}

type KsVirtualServer struct {
	Name        string                `json:"name"`
	Namespace   string                `json:"namespace"`
	IP          string                `json:"ip"`
	Port        int32                 `json:"port"`
	ClientSSL   string                `json:"clientssl",omitempty`
	ServerSSL   string                `json:"serverssl",omitempty`
	Redirect    bool                  `json:"redirect",omitempty`
	DefPersist  string                `json:"persist",omitempty`
	FBPersist   string                `json:"fallbackPersist",omitempty`
	LBMode      string                `json:"lbmode",omitempty`
	IRules      []string              `json:"rules",omitempty`
	Members     []KsVSMember          `json:"members",omitempty`
	Monitor     KsVSMonitorAttributes `json:"monitors",omitempty`
	IbEnabled   bool                  `json:"ibenabled",omitempty`
	IbDynamicIP bool                  `json:"ibdynamicip",omitempty`
	IbHostname  string                `json:"ibhostname",omitempty`
}

type KubernetesState []KsVirtualServer

func getKubernetesState() (KubernetesState, error) {

	log.WithFields(log.Fields{
		"thread": "Kubernetes",
	}).Info("Refreshing the local state cache")

	var ks KubernetesState

	ingresses, err := clientset.ExtensionsV1beta1().Ingresses("").List(metav1.ListOptions{})
	if err != nil {
		return ks, err
	}
	log.Debug("Successfully fetched all Ingress objects from Kubernetes")

	services, err := clientset.CoreV1().Services("").List(metav1.ListOptions{})
	if err != nil {
		return ks, err
	}
	log.Debug("Successfully fetched all Service objects from Kubernetes")

	// Loop through the Ingress objects, building complete virtual server objects

	for _, ingress := range ingresses.Items {

		// Set basic parameters of the virtual server

		var vs KsVirtualServer

		vs.Name = ingress.GetName()
		vs.Namespace = ingress.GetNamespace()

		if value, ok := ingress.ObjectMeta.Annotations["infoblox-ipam/hostname"]; ok == true {
			vs.IbHostname = value
		}

		if value, ok := ingress.ObjectMeta.Annotations["infoblox-ipam/ip-allocation"]; ok == true {
			if value == "dynamic" {
				vs.IbDynamicIP = true
				vs.IbEnabled = true
			} else {
				log.WithFields(log.Fields{
					"ingress":   vs.Name,
					"namespace": vs.Namespace,
				}).Debug("Unknown value for infoblox-ipam/ip-allocation")
			}
		}

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/ip"]; ok == true {
			if ip := net.ParseIP(value); ip != nil {
				vs.IP = value
			} else {
				log.WithFields(log.Fields{
					"ingress":   vs.Name,
					"namespace": vs.Namespace,
					"ip":        value,
				}).Error("Invalid IP address for ip annotation")
			}
		} else {
			if !vs.IbEnabled {
				log.WithFields(log.Fields{
					"ingress":   vs.Name,
					"namespace": vs.Namespace,
				}).Info("No IP address, creating a headless virtual server")
			}
		}

		if vs.IP != "" && vs.IbHostname != "" {
			vs.IbEnabled = true // If we have a fixed IP, and a hostname, manage the DNS entry only
			vs.IbDynamicIP = false
		}

		if len(ingress.Spec.TLS) != 0 {
			vs.ClientSSL = ingress.Spec.TLS[0].SecretName
			vs.Redirect = true
			if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/https-port"]; ok == true {
				port, _ := strconv.ParseInt(value, 10, 32)
				vs.Port = int32(port)
			} else {
				vs.Port = 443
			}
			if value, ok := ingress.ObjectMeta.Annotations["ingress.kubernetes.io/ssl-redirect"]; ok == true {
				if value == "false" {
					vs.Redirect = false
				}
			}
		} else {
			if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/http-port"]; ok == true {
				port, _ := strconv.ParseInt(value, 10, 32)
				vs.Port = int32(port)
			} else {
				vs.Port = 80
			}
		}

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/health"]; ok == true {
			var monitors []KsVSMonitorAttributes

			err := json.Unmarshal([]byte(value), &monitors)
			if err != nil {
				log.Debug("health monitor JSON parsing failed")
			} else {
				vs.Monitor = monitors[0]
			}
		}

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/serverssl"]; ok == true {
			vs.ServerSSL = value
			if vs.Monitor.Type == "" {
				vs.Monitor.Type = "https"
			}
		}

		if vs.Monitor.Type == "" {
			vs.Monitor.Type = "http"
		}

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/rules"]; ok == true {
			parts := strings.Split(value, ",")
			for idx := range parts {
				vs.IRules = append(vs.IRules, parts[idx])
			}
		}

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/balance"]; ok == true {
			vs.LBMode = value
		}

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/defaultPersist"]; ok == true {
			vs.DefPersist = value
		}

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/fallbackPersist"]; ok == true {
			vs.FBPersist = value
		}

		// Find a matching service

		var service v1.Service

		err = fmt.Errorf("Not found")
		for _, service = range services.Items {
			if ingress.Spec.Backend != nil {
				if service.GetName() == ingress.Spec.Backend.ServiceName && service.GetNamespace() == vs.Namespace {
					err = nil
					break
				}
			}
		}
		if err != nil {
			log.WithFields(log.Fields{
				"ingress":   vs.Name,
				"namespace": vs.Namespace,
				"service":   service.GetName(),
			}).Info("The service was not found, skipping this Ingress")
			continue
		}

		// Build an array of pods and attach it to the virtual server as members
		// Proceed (with a warning to user) if there are no pods
		// Proceed (with a warning to user) if a pod is not running (there is no IP for non-runnig pods)

		set := labels.Set(service.Spec.Selector).String()

		pods, err := clientset.Core().Pods(vs.Namespace).List(metav1.ListOptions{LabelSelector: set})
		if err == nil {
			for _, pod := range pods.Items {
				var member KsVSMember

				if pod.Status.Phase == "Running" {
					member.Name = pod.GetName()
					member.IP = pod.Status.PodIP
					if ingress.Spec.Backend != nil {
						if ingress.Spec.Backend.ServicePort.Type == intstr.Int {
							member.Port = int32(ingress.Spec.Backend.ServicePort.IntValue())
						} else {
							switch ingress.Spec.Backend.ServicePort.String() {
							case "http":
								member.Port = 80
							case "https":
								member.Port = 443
							default:
								log.WithFields(log.Fields{
									"ingress":   vs.Name,
									"namespace": vs.Namespace,
									"pod":       member.Name,
									"ip":        member.IP,
									"port":      ingress.Spec.Backend.ServicePort.String(),
								}).Debug("Unknown port type")
							}
						}
					}
					vs.Members = append(vs.Members, member)
					log.WithFields(log.Fields{
						"ingress":   vs.Name,
						"namespace": vs.Namespace,
						"pod":       member.Name,
						"ip":        member.IP,
						"port":      member.Port,
					}).Debug("Adding a pod to the virtual server")
				} else {
					log.WithFields(log.Fields{
						"ingress":   vs.Name,
						"namespace": vs.Namespace,
						"pod":       pod.GetName(),
					}).Infof("Skipping a pod that is not running")
				}
			}
		} else {
			log.WithFields(log.Fields{
				"ingress":   vs.Name,
				"namespace": vs.Namespace,
			}).Debug("Call to fetch pods failed")
			log.Debug(err.Error())
		}

		if vs.Members == nil {
			log.WithFields(log.Fields{
				"ingress":   vs.Name,
				"namespace": vs.Namespace,
			}).Debug("No pods were found, creating empty Ingress")
		}

		// Attach the new virtual server to the slice

		ks = append(ks, vs)

		// Update the IP status field in Kubernetes if we can find a matching
		// F5 virtual server object with an IP assigned

		f5VSName := f5VirtualServerName(vs)

		for _, f5vs := range f5State.Virtuals {

			if f5VSName == f5vs.Name {

				// We found a virtual server that matches, see if there's a valid IP address
				// set on it

				tmp := strings.Split(f5vs.Destination, "/")
				tmp = strings.Split(tmp[2], "%")
				tmp = strings.Split(tmp[0], ":")
				f5IpAddr := tmp[0]

				if f5IpAddr == "" || f5IpAddr == "0.0.0.0" {
					break
				}

				// Ok, we have a valid IP address, if the F5 IP address differs from the
				// IP address already set on the Ingress, change the ingress status to
				// to the IP address of the virtual server on the F5.

				if len(ingress.Status.LoadBalancer.Ingress) > 0 {
					if ingress.Status.LoadBalancer.Ingress[0].IP == f5IpAddr {
						break
					}
				}
				newStatus := []v1.LoadBalancerIngress{
					v1.LoadBalancerIngress{
						IP: f5IpAddr,
					},
				}
				ingress.Status.LoadBalancer.Ingress = newStatus
				log.WithFields(log.Fields{
					"ingress":   vs.Name,
					"ip":        f5IpAddr,
					"namespace": vs.Namespace,
					"thread":    "Kubernetes",
				}).Info("Updating an ingress with the IP address from the F5")
				_, err := clientset.ExtensionsV1beta1().Ingresses(ingress.Namespace).UpdateStatus(&ingress)
				if err != nil {
					log.Error(err.Error())
				}
				break
			}
		}
	}

	return ks, nil
}

var version string

func main() {

	// Say Hello!

	log.WithFields(log.Fields{
		"version": version,
	}).Info("F5-ingress-ctlr starting")
	// initialize the Kubernetes connection

	if ok := os.Getenv("DEBUG"); ok != "" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	err := initKubernetes()
	if err != nil || clientset == nil {
		log.Error("Could not initialize a connection to Kubernetes")
		log.Error(err.Error())
		os.Exit(1)
	}

	refreshInterval := 900 // default is 15 minutes
        if refreshStr := os.Getenv("REFRESH_INTERVAL"); refreshStr  != "" {
		val, err := strconv.Atoi(refreshStr)
		if err == nil {
			refreshInterval = val * 60
		}
	}
	log.WithFields(log.Fields{
		"interval": refreshInterval/60,
	}).Info("Full refresh interval (minutes)")

	k8sPollInterval := 15 // default is 15 seconds
	if refreshStr := os.Getenv("K8S_POLL_INTERVAL"); refreshStr != "" {
		val, err := strconv.Atoi(refreshStr)
		if err == nil {
			k8sPollInterval = val
		}
	}
	log.WithFields(log.Fields{
		"interval": k8sPollInterval,
	}).Info("Kubernetes polling interval (seconds)")

	if globalConfig.Partition = os.Getenv("BIGIP_PARTITION"); globalConfig.Partition == "" {
		log.Error("The environment variable BIGIP_PARTITION must be set")
		os.Exit(1)
	}
	if globalConfig.F5Host = os.Getenv("BIGIP_HOST"); globalConfig.F5Host == "" {
		log.Error("The environment variable BIGIP_HOST must be set")
		os.Exit(1)
	}
	log.WithFields(log.Fields{
		"host": globalConfig.F5Host,
	}).Info("Configured an F5 host address")

	if globalConfig.RouteDomain = os.Getenv("F5_ROUTE_DOMAIN"); globalConfig.RouteDomain == "" {
		log.Error("The environment variable F5_ROUTE_DOMAIN must be set")
		os.Exit(1)
	}
	log.WithFields(log.Fields{
		"routeDomain": globalConfig.RouteDomain,
	}).Info("Configured an F5 route domain")

	globalConfig.IbActive = false
	if globalConfig.VIPCIDR = os.Getenv("INFOBLOX_SUBNET"); globalConfig.VIPCIDR != "" {
		log.WithFields(log.Fields{
			"subnet": globalConfig.VIPCIDR,
		}).Info("Configured an Infoblox subnet for IP allocations")
	}

	if globalConfig.IbHost = os.Getenv("INFOBLOX_HOST"); globalConfig.IbHost != "" {
		log.WithFields(log.Fields{
			"host": globalConfig.IbHost,
		}).Info("Configured an Infoblox host address")
	}

	f5user_b, err := ioutil.ReadFile("/secret/f5_user")
	if err != nil {
		log.Error("The secret f5_user could not be read from the secret volume")
		log.Error("Make sure the secrets are mounted at /secret on the container")
		log.Error(err.Error())
		os.Exit(1)
	}
	globalConfig.F5User = string(f5user_b)

	f5pass_b, err := ioutil.ReadFile("/secret/f5_pass")
	if err != nil {
		log.Error("The secret f5_pass could not be read from the secret volume")
		log.Error("Make sure the secrets are mounted at /secret on the container")
		log.Error(err.Error())
		os.Exit(1)
	}
	globalConfig.F5Pass = string(f5pass_b)
	log.WithFields(log.Fields{
		"username": globalConfig.F5User,
	}).Info("Configured F5 credentials")

	ibUser_b, err := ioutil.ReadFile("/secret/infoblox_user")
	if err == nil {
		globalConfig.IbUser = string(ibUser_b)
	}

	ibPass_b, err := ioutil.ReadFile("/secret/infoblox_pass")
	if err == nil {
		globalConfig.IbPass = string(ibPass_b)
	}

	if globalConfig.IbUser != "" && globalConfig.IbPass != "" {
		log.WithFields(log.Fields{
			"username": globalConfig.IbUser,
		}).Info("Configured Infoblox credentials")
	}

	globalConfig.IbActive = false

	// clear F5 LTM state

	for true {

		err = ibRefreshState()
		if err != nil {
			log.Error("Could not refresh the current state from the Infoblox")
			log.Error(err.Error())
			time.Sleep(30 * time.Second)
			continue
		}

		f5State.Virtuals = []bigip.VirtualServer{}
		f5State.Pools = []bigip.Pool{}
		f5State.Monitors = []bigip.Monitor{}
		f5State.Nodes = []bigip.Node{}

		err = buildCurrentLTMState()
		if err != nil {
			log.Error("Could not fetch current state from F5")
			log.Error(err.Error())
			time.Sleep(30 * time.Second)
			continue
		}

		// Execute 60 times, with 15 seconds in between, so full F5 state is pulled every
		// 15 minutes

		for i := 0; i < (refreshInterval / k8sPollInterval); i++ {
			desiredState, err := getKubernetesState()
			if err != nil {
				log.Error("Could not fetch desired state from Kubernetes")
				log.Error(err.Error())
				time.Sleep(15 * time.Second)
				continue
			}

			err = applyF5Diffs(desiredState)
			if err != nil {
				log.Error("Could not apply the Kubernetes state to F5")
				log.Error(err.Error())
				time.Sleep(15 * time.Second)
				continue
			}
			// Temporarily here
			copyOfibAddrs := make([]ibAddr, len(ibAddrs))
			copy(copyOfibAddrs, ibAddrs)
			for _, iba := range copyOfibAddrs {
				found := false
				for _, f5vs := range f5State.Virtuals {
					tmp := strings.Split(f5vs.Destination, "/")
					tmp = strings.Split(tmp[2], "%")
					tmp = strings.Split(tmp[0], ":")
					ipAddr := tmp[0]

					if ipAddr == iba.IP {
						found = true
						break
					}
				}
				if !found {
					if err := ibReleaseIP(iba.IP); err != nil {
						log.Error(err.Error())
					}
				}
			}
			time.Sleep(time.Duration(k8sPollInterval) * time.Second)
		}
	}
}
