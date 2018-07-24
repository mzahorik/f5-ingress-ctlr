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
	"encoding/json"
	"flag"
	"fmt"
	"net"
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
	Partition string
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
		log.Debugf("Connected using in-pod credentials")
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
				"monitor": monitor.Name,
				"pool":    pool.Name,
				"thread":  "F5",
			}).Infof("Removing the monitor reference ****TODO****")
		}
	}

	// Call the F5 to delete the monitor

	log.WithFields(log.Fields{
		"monitor": monitor.Name,
		"thread":  "F5",
	}).Infof("Removing the monitor from the F5")

	if err := f5.DeleteMonitor(monitor.FullPath, monitor.MonitorType); err != nil {
		return err
	}

	// Remove it from the array of monitors in the F5 state cache

	log.WithFields(log.Fields{
		"node":   monitor.Name,
		"thread": "F5",
	}).Debugf("Removing the monitor from the state cache")

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

	for _, pool := range f5State.Pools {

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
						"pool":   pool.Name,
						"member": poolMember.FullPath,
						"thread": "F5",
					}).Debugf("The pool member isn't in <node>:<port> format. Skipping it")
					continue
				}

				if splitString[0] == node.FullPath {
					poolMemberConfig := &bigip.PoolMember{
						FullPath:  poolMember.FullPath,
						Name:      poolMember.Name,
						Partition: globalConfig.Partition,
					}
					log.WithFields(log.Fields{
						"pool":   pool.Name,
						"member": poolMember.Name,
						"thread": "F5",
					}).Infof("Removing the pool member from the F5")
					if err := f5.RemovePoolMember(pool.FullPath, poolMemberConfig); err != nil {
						return err
					}

					log.WithFields(log.Fields{
						"member": poolMember.Name,
						"pool":   pool.Name,
						"thread": "F5",
					}).Debugf("Removing the pool member from the state cache")
					newPoolMembers := []bigip.PoolMember{}
					for _, pm := range *pool.Members {
						if pm.FullPath != poolMember.FullPath {
							newPoolMembers = append(newPoolMembers, pm)
						}
					}

					pool.Members = &newPoolMembers
					break // Don't scan the remaining pool members
				}
			}
		}
	}

	// Call the F5 to delete the node

	log.WithFields(log.Fields{
		"node":   node.Name,
		"thread": "F5",
	}).Infof("Removing the node from the F5")

	if err := f5.DeleteNode(node.FullPath); err != nil {
		return err
	}

	// Remove it from the array of nodes in the F5 state cache

	log.WithFields(log.Fields{
		"node":   node.Name,
		"thread": "F5",
	}).Debugf("Removing the node from the state cache")

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
			}).Infof("Removing the pool reference ****TODO****")
		}
	}

	// Call the F5 to delete the pool

	log.WithFields(log.Fields{
		"pool":   pool.Name,
		"thread": "F5",
	}).Infof("Removing the pool from the F5")

	if err := f5.DeletePool(pool.FullPath); err != nil {
		return err
	}

	// Remove it from the array of pools in the F5 state cache

	log.WithFields(log.Fields{
		"pool":   pool.Name,
		"thread": "F5",
	}).Debugf("Removing the pool from the state cache")

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
		"virtualServer": vs.Name,
	}).Infof("Removing the virtual server from the F5")

	if err := f5.DeleteVirtualServer(vs.FullPath); err != nil {
		return err
	}

	// Remove it from the array of virtual servers in the F5 state cache

	log.WithFields(log.Fields{
		"thread":        "F5",
		"virtualServer": vs.Name,
	}).Debugf("Removing the virtual server from the state cache")

	for idx, stateVS := range f5State.Virtuals {
		if vs.FullPath == stateVS.FullPath {
			f5State.Virtuals = append(f5State.Virtuals[:idx], f5State.Virtuals[idx+1:]...)
			break
		}
	}

	return nil
}

func applyF5Diffs(k8sState KubernetesState) error {

	// Step through virtual servers, creating as necessary

	metadata := bigip.Metadata{
		Name:    "f5-ingress-ctlr-managed",
		Value:   "true",
		Persist: "true",
	}

	description := "Managed by Kubernetes. Please do not make manual changes."

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
		}
		if !found {
			if err := deleteVirtualServer(f5vs); err != nil {
				log.Errorf(err.Error())
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
				log.Errorf(err.Error())
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
				log.Errorf(err.Error())
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
				log.Errorf(err.Error())
			}
		}
	}

	var notNewVirtuals KubernetesState
	for _, vs := range k8sState {
		vsName := f5VirtualServerName(vs)
		found := false
		for _, f5vs := range f5State.Virtuals {
			if f5vs.Name == vsName {
				found = true
				break
			}
		}
		if found {
			notNewVirtuals = append(notNewVirtuals, vs)
		} else {

			monitorConfig := &bigip.Monitor{
				Description:   description,
				Interval:      vs.Monitor.Interval,
				Name:          f5MonitorName(vs),
				Partition:     globalConfig.Partition,
				ReceiveString: vs.Monitor.Receive,
				SendString:    vs.Monitor.Send,
			}
			monitorConfig.Metadata = append([]bigip.Metadata{}, metadata)

			log.WithFields(log.Fields{
				"name": monitorConfig.Name,
				"type": vs.Monitor.Type,
			}).Debugf("Adding new monitor")
			log.Debugf(fmt.Sprintf("Config: %+v", monitorConfig))

			monitorOk := true
			if err := f5.AddMonitor(monitorConfig, vs.Monitor.Type); err != nil {
				log.WithFields(log.Fields{
					"name": monitorConfig.Name,
					"type": vs.Monitor.Type,
				}).Infof("Monitor creation failed, proceeding without it")
				log.Infof("Error: " + err.Error())
				monitorOk = false
			}

			poolConfig := &bigip.Pool{
				Description:       description,
				LoadBalancingMode: vs.LBMode,
				Name:              f5PoolName(vs),
				Partition:         globalConfig.Partition,
			}
			poolConfig.Metadata = append([]bigip.Metadata{}, metadata)
			if monitorOk {
				poolConfig.Monitor = fmt.Sprintf("/%s/%s", globalConfig.Partition, f5MonitorName(vs))
			}

			poolMembers := []bigip.PoolMember{}

			for idx, member := range vs.Members {
				nodeName := f5NodeName(vs, idx)
				nodeConfig := &bigip.Node{
					Description: description,
					Address:     member.IP,
					Name:        nodeName,
					Partition:   globalConfig.Partition,
				}
				nodeConfig.Metadata = append([]bigip.Metadata{}, metadata)
				if err := f5.AddNode(nodeConfig); err != nil {
					log.WithFields(log.Fields{
						"node": nodeConfig.Name,
					}).Infof("Node creation failed, proceeding without it")
					log.Infof("Error: " + err.Error())
					continue
				}

				memberName := f5PoolMemberName(vs, idx)
				log.WithFields(log.Fields{
					"pool": poolConfig.Name,
					"name": memberName,
					"ip":   member.IP,
				}).Debugf("Adding pool member")
				memberConfig := bigip.PoolMember{
					Description: description,
					Name:        memberName,
					Partition:   globalConfig.Partition,
				}
				memberConfig.Metadata = append([]bigip.Metadata{}, metadata)
				poolMembers = append(poolMembers, memberConfig)
			}

			poolConfig.Members = &poolMembers

			log.WithFields(log.Fields{
				"name": poolConfig.Name,
			}).Debugf("Creating new pool")
			log.Debugf(fmt.Sprintf("Config: %+v", poolConfig))

			poolOk := true
			if err := f5.AddPool(poolConfig); err != nil {
				log.WithFields(log.Fields{
					"name": poolConfig.Name,
				}).Infof("Pool creation failed, proceeding without it")
				log.Infof("Error: " + err.Error())
				poolOk = false
			}

			vsNewIP := strings.Replace(vs.IP, "10.226.197", "10.226.195", 1) // A temporary thing while working in the lab to use existing ingress on new network

			vsConfig := &bigip.VirtualServer{
				Description: description,
				Destination: fmt.Sprintf("/%s/%s:%d", globalConfig.Partition, vsNewIP, vs.Port),
				IPProtocol:  "tcp",
				Mask:        "255.255.255.255",
				Name:        vsName,
				Partition:   globalConfig.Partition,
				Source:      "0.0.0.0/0",
			}
			vsConfig.Metadata = append([]bigip.Metadata{}, metadata)
			vsConfig.SourceAddressTranslation.Type = "automap"
			if vs.DefPersist != "" {
				splitString := strings.Split(vs.DefPersist, "/")
				defPersist := bigip.Persistence{
					Name:      splitString[2],
					Partition: splitString[1],
					Default:   "yes",
				}
				vsConfig.Persistence = append([]bigip.Persistence{}, defPersist)
			}
			if vs.FBPersist != "" {
				vsConfig.FallbackPersistence = vs.FBPersist
			}
			vsConfig.Profiles = []bigip.Profile{}
			httpProfile := bigip.Profile{
				Context:   "all",
				Name:      "http",
				Partition: "Common",
			}
			vsConfig.Profiles = append(vsConfig.Profiles, httpProfile)
			tcpProfile := bigip.Profile{
				Context:   "all",
				Name:      "tcp",
				Partition: "Common",
			}
			vsConfig.Profiles = append(vsConfig.Profiles, tcpProfile)
			if vs.ClientSSL != "" {
				splitString := strings.Split(vs.ClientSSL, "/")
				clientSSLProfile := bigip.Profile{
					Context:   "clientside",
					Name:      splitString[2],
					Partition: splitString[1],
				}
				vsConfig.Profiles = append(vsConfig.Profiles, clientSSLProfile)
			}
			if vs.ServerSSL != "" {
				splitString := strings.Split(vs.ServerSSL, "/")
				serverSSLProfile := bigip.Profile{
					Context:   "serverside",
					Name:      splitString[2],
					Partition: splitString[1],
				}
				vsConfig.Profiles = append(vsConfig.Profiles, serverSSLProfile)
			}
			if poolOk {
				vsConfig.Pool = fmt.Sprintf("/%s/%s", globalConfig.Partition, f5PoolName(vs))
			}

			if len(vs.IRules) > 0 {
				vsConfig.Rules = vs.IRules
			}

			log.WithFields(log.Fields{
				"name": vsConfig.Name,
			}).Debugf("Adding new virtual server")
			log.Debugf(fmt.Sprintf("Config: %+v", vsConfig))

			log.Debugf("Creating virtual server")
			if err := f5.AddVirtualServer(vsConfig); err != nil {
				log.Infof("Virtual server failed to create, skipping virtual server")
				log.WithFields(log.Fields{
					"name": vsConfig.Name,
				}).Infof("Virtual server creation failed, proceeding without it")
				log.Infof("Error: " + err.Error())
			}
		}

	}

	// Add in new nodes to existing pools

	for _, vs := range notNewVirtuals {
		for idx, member := range vs.Members {
			nodeName := f5NodeName(vs, idx)
			found := false
			for _, f5node := range f5State.Nodes {
				if f5node.Name == nodeName {
					found = true
					break
				}
			}
			if !found {
				// Add a node, associate it with this pool's virtual server
				nodeConfig := &bigip.Node{
					Description: description,
					Address:     member.IP,
					Name:        nodeName,
					Partition:   globalConfig.Partition,
				}
				nodeConfig.Metadata = append([]bigip.Metadata{}, metadata)
				if err := f5.AddNode(nodeConfig); err != nil {
					log.WithFields(log.Fields{
						"node": nodeConfig.Name,
					}).Infof("Node creation failed, proceeding without it")
					log.Infof("Error: " + err.Error())
					continue
				}

				poolName := f5PoolName(vs)
				poolFullPath := "/" + globalConfig.Partition + "/" + poolName

				memberName := f5PoolMemberName(vs, idx)
				log.WithFields(log.Fields{
					"pool": poolName,
					"name": memberName,
					"ip":   member.IP,
				}).Debugf("Adding pool member")
				memberConfig := &bigip.PoolMember{
					Description: description,
					Name:        memberName,
					Partition:   globalConfig.Partition,
				}
				memberConfig.Metadata = append([]bigip.Metadata{}, metadata)
				log.Debugf(fmt.Sprintf("Config: %+v", memberConfig))
				log.Debugf(fmt.Sprintf("PoolFullPath: %s", poolFullPath))
				if err := f5.CreatePoolMember(poolFullPath, memberConfig); err != nil {
					log.WithFields(log.Fields{
						"member": memberName,
						"pool":   poolName,
					}).Infof("Pool member creation failed, proceeding without it")
				}
			}
		}
	}

	return nil
}

func buildCurrentLTMState() error {

	var f5_user, f5_password, f5_host string

	var err error

	if f5_user = os.Getenv("F5_USER"); f5_user == "" {
		return fmt.Errorf("F5_USER environment variable must be set")
	}

	if f5_password = os.Getenv("F5_PASSWORD"); f5_password == "" {
		return fmt.Errorf("F5_PASSWORD environment variable must be set")
	}

	if f5_host = os.Getenv("F5_HOST"); f5_host == "" {
		return fmt.Errorf("F5_HOST environment variable must be set")
	}

	f5, err = bigip.NewTokenSession(f5_host, f5_user, f5_password, "tmos", &bigip.ConfigOptions{})

	if err != nil {
		log.Debugf("Failed to get token")
		return err
	}

	log.Debugf("Connected to F5")

	virtualServers, err := f5.VirtualServersForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 virtual server information")
		return err
	}

	pools, err := f5.PoolsForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 pool information")
		return err
	}

	monitors, err := f5.MonitorsForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 monitor information")
		return err
	}

	nodes, err := f5.NodesForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 node information")
		return err
	}

	// Clean the virtual server list - only copy over virtual server
	// entries that are in our specified partition, and have a
	// metadata entry of "f5-ingress-ctlr-managed" set to "true"

	for _, virtualServer := range virtualServers.VirtualServers {
		if virtualServer.Partition == globalConfig.Partition {
			for _, metadata := range virtualServer.Metadata {
				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
					log.WithFields(log.Fields{
						"thread": "F5",
						"vs":     virtualServer.Name,
					}).Debugf("Adding virtual server to state cache")
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
						}).Debugf("Failed to fetch pool members")
					} else {
						for _, pm := range poolMembers.PoolMembers {
							log.WithFields(log.Fields{
								"pool":       pool.Name,
								"poolMember": pm.Name,
								"thread":     "F5",
							}).Debugf("Adding pool member to state cache")
						}
						pool.Members = &poolMembers.PoolMembers
					}
					log.WithFields(log.Fields{
						"pool":   pool.Name,
						"thread": "F5",
					}).Debugf("Adding pool to state cache")
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
				}).Debugf("Adding monitor to state cache")
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
					}).Debugf("Adding node to state cache")
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
	Name       string                `json:"name"`
	Namespace  string                `json:"namespace"`
	IP         string                `json:"ip"`
	Port       int32                 `json:"port"`
	ClientSSL  string                `json:"clientssl",omitempty`
	ServerSSL  string                `json:"serverssl",omitempty`
	Redirect   bool                  `json:"redirect",omitempty`
	DefPersist string                `json:"persist",omitempty`
	FBPersist  string                `json:"fallbackPersist",omitempty`
	LBMode     string                `json:"lbmode",omitempty`
	IRules     []string              `json:"rules",omitempty`
	Members    []KsVSMember          `json:"members",omitempty`
	Monitor    KsVSMonitorAttributes `json:"monitors",omitempty`
}

type KubernetesState []KsVirtualServer

func getKubernetesState() (KubernetesState, error) {

	var ks KubernetesState

	ingresses, err := clientset.ExtensionsV1beta1().Ingresses("").List(metav1.ListOptions{})
	if err != nil {
		return ks, err
	}
	log.Debugf("Successfully fetched all Ingress objects from Kubernetes")

	services, err := clientset.CoreV1().Services("").List(metav1.ListOptions{})
	if err != nil {
		return ks, err
	}
	log.Debugf("Successfully fetched all Service objects from Kubernetes")

	// Loop through the Ingress objects, building complete virtual server objects

	for _, ingress := range ingresses.Items {

		// Set basic parameters of the virtual server

		var vs KsVirtualServer

		vs.Name = ingress.GetName()
		vs.Namespace = ingress.GetNamespace()

		if value, ok := ingress.ObjectMeta.Annotations["virtual-server.f5.com/ip"]; ok == true {
			if ip := net.ParseIP(value); ip != nil {
				vs.IP = value
			} else {
				log.WithFields(log.Fields{
					"ingress":   vs.Name,
					"namespace": vs.Namespace,
					"ip":        value,
				}).Errorf("Invalid IP address for ip annotation")
			}
		} else {
			log.WithFields(log.Fields{
				"ingress":   vs.Name,
				"namespace": vs.Namespace,
			}).Infof("No IP address, creating headless virtual server")
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
				log.Debugf("health monitor JSON parsing failed")
			}
			vs.Monitor = monitors[0]
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
			}).Infof("Service not found, skipping this Ingress")
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
								}).Debugf("Unknown port type")
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
					}).Debugf("Adding pod to virtual server")
				} else {
					log.WithFields(log.Fields{
						"ingress":   vs.Name,
						"namespace": vs.Namespace,
						"pod":       pod.GetName(),
					}).Infof("Skipping pod that is not running")
				}
			}
		} else {
			log.WithFields(log.Fields{
				"ingress":   vs.Name,
				"namespace": vs.Namespace,
			}).Debugf("Call to fetch pods failed")
			log.Debugf(err.Error())
		}

		if vs.Members == nil {
			log.WithFields(log.Fields{
				"ingress":   vs.Name,
				"namespace": vs.Namespace,
			}).Debugf("No pods found, creating empty Ingress")
		}

		// Attach the new virtual server to the slice

		ks = append(ks, vs)
	}

	return ks, nil
}

var version string

func main() {

	// Say Hello!

	log.WithFields(log.Fields{
		"version": version,
	}).Infof("F5-ingress-ctlr starting")
	// initialize the Kubernetes connection

	log.SetLevel(log.DebugLevel)

	err := initKubernetes()
	if err != nil || clientset == nil {
		log.Error("Could not initialize a connection to Kubernetes")
		log.Error(err.Error())
		os.Exit(1)
	}

	globalConfig.Partition = "k8s-auto-ny2"

	// clear F5 LTM state

	for true {

		f5State.Virtuals = []bigip.VirtualServer{}
		f5State.Pools = []bigip.Pool{}
		f5State.Monitors = []bigip.Monitor{}
		f5State.Nodes = []bigip.Node{}

		err = buildCurrentLTMState()
		if err != nil {
			log.Errorf("Could not fetch current state from F5")
			log.Errorf(err.Error())
			os.Exit(1)
		}

		//	for true {
		desiredState, err := getKubernetesState()
		if err != nil {
			log.Error("Could not fetch desired state from Kubernetes")
			log.Error(err.Error())
			os.Exit(1)
		}

		err = applyF5Diffs(desiredState)
		if err != nil {
			log.Error("Could not apply Kubernetes state to F5")
			log.Error(err.Error())
			os.Exit(1)
		}
		time.Sleep(15 * time.Second)
	}
}
