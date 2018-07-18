/*
Copyright 2016 The Kubernetes Authors.

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

/*
** deleteMonitor
**
** Takes an index into the f5State.Monitors slice, and deletes that monitor
** off the F5. If successful, it is removed from the f5State.Monitors slice.
**
** Prior to deleting the monitor, all pools in our partition are scanned
** to see if there's an association with the monitor, and if so, the
** monitor is removed from the pool before deleting the monitor.
**
** If anything went wrong, the error is returned to the caller to handle.
 */

func deleteMonitor(index int) error {

	monitor := f5State.Monitors[index]

	for _, pool := range f5State.Pools {

		if pool.Monitor == monitor.FullPath {

			log.WithFields(log.Fields{
				"monitor": monitor.Name,
				"pool":    pool.Name,
				"thread":  "F5",
			}).Infof("Removing monitor from pool. ****TODO****")
		}
	}

	// Call the F5 to delete it

	log.WithFields(log.Fields{
		"monitor": monitor.Name,
		"thread":  "F5",
	}).Infof("Removing monitor.")

	if err := f5.DeleteMonitor(monitor.FullPath, monitor.MonitorType); err != nil {
		return err
	}

	// Remove it from the list of virtuals in the F5 state

	f5State.Monitors = append(f5State.Monitors[:index], f5State.Monitors[index+1:]...)

	return nil
}

/*
** deleteNode
**
** Takes an index into the f5State.Nodes slice, and deletes that node off the F5.
** If successful, it is removed from the f5State.Nodes slice.
**
** Prior to deleting the node, all pool members in our partition are scanned
** to see if there's an association with the node, and if so, the pool member
** is removed from the pool before deleting the node.
**
** If anything went wrong, the error is returned to the caller to handle.
 */

func deleteNode(index int) error {

	node := f5State.Nodes[index]

	for _, pool := range f5State.Pools {

		if pool.Members != nil {
			log.Debugf(fmt.Sprintf("pool.Members: %+v", pool.Members))
		}

		poolMembers, err := f5.PoolMembers(pool.FullPath)
		if err != nil {
			log.WithFields(log.Fields{
				"error":  err.Error(),
				"pool":   pool.Name,
				"thread": "F5",
			}).Debugf("Failed to get pool members.")
			continue
		}

		for _, poolMember := range poolMembers.PoolMembers {
			splitString := strings.Split(poolMember.FullPath, ":")
			if len(splitString) < 2 {
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
				}).Infof("Removing pool member from pool.")
				if err := f5.RemovePoolMember(pool.FullPath, poolMemberConfig); err != nil {
					log.WithFields(log.Fields{
						"error":  err.Error(),
						"member": poolMember.Name,
						"pool":   pool.Name,
						"thread": "F5",
					}).Debugf("Failed to remove pool member.")
				}
				// ****TODO**** If pool.Members exist, remove it here to keep state up to date
			}
		}
	}

	// Call the F5 to delete it

	log.WithFields(log.Fields{
		"node":   node.Name,
		"thread": "F5",
	}).Infof("Removing node.")

	if err := f5.DeleteNode(node.FullPath); err != nil {
		return err
	}

	// Remove it from the list of nodes in the F5 state

	log.Debugf("f5State.Nodes before:")
	for _, node := range f5State.Nodes {
		log.Debugf(fmt.Sprintf("   %s", node.Name))
	}
	f5State.Nodes = append(f5State.Nodes[:index], f5State.Nodes[index+1:]...)
	log.Debugf("f5State.Nodes after:")
	for _, node := range f5State.Nodes {
		log.Debugf(fmt.Sprintf("   %s", node.Name))
	}

	return nil
}

/*
** deletePool
**
** Takes an index into the f5State.Pools slice, and deletes that pool off the F5.
** If successful, it is removed from the f5State.Pools slice.
**
** Prior to deleting the pool, all virtual servers in our partition are scanned
** to see if there's an association with the pool, and if so, the pool is
** removed from the virtual server before deleting the pool.
**
** If anything went wrong, the error is returned to the caller to handle.
 */

func deletePool(index int) error {

	pool := f5State.Pools[index]

	for _, vs := range f5State.Virtuals {

		if vs.Pool == pool.FullPath {

			log.WithFields(log.Fields{
				"pool":   pool.Name,
				"thread": "F5",
				"vs":     vs.Name,
			}).Infof("Removing pool from virtual server. ****TODO****")
		}
	}

	// Call the F5 to delete it

	log.WithFields(log.Fields{
		"pool":   pool.Name,
		"thread": "F5",
	}).Infof("Removing pool.")

	if err := f5.DeletePool(pool.FullPath); err != nil {
		return err
	}

	// Remove it from the list of pools in the F5 state

	f5State.Pools = append(f5State.Pools[:index], f5State.Pools[index+1:]...)

	return nil
}

/*
** deleteVirtualServer
**
** Takes an index into the f5State.Virtuals slice, and deletes that virtual server
** off the F5.  If successful, it is also removed from the f5State.Virtuals slice.
**
** If anything went wrong, the error is returned to the caller to handle.
 */

func deleteVirtualServer(index int) error {

	// Get the virtual server

	vs := f5State.Virtuals[index]

	// Call the F5 to delete it

	log.WithFields(log.Fields{
		"thread": "F5",
		"vs":     vs.Name,
	}).Infof("Removing virtual server.")

	if err := f5.DeleteVirtualServer(vs.FullPath); err != nil {
		return err
	}

	// Remove it from the list of virtuals in the F5 state

	f5State.Virtuals = append(f5State.Virtuals[:index], f5State.Virtuals[index+1:]...)

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

	for idx, f5vs := range f5State.Virtuals {
		found := false
		for _, vs := range k8sState {
			vsName := f5VirtualServerName(vs)
			if f5vs.Name == vsName {
				found = true
				break
			}
		}
		if !found {
			if err := deleteVirtualServer(idx); err != nil {
				log.Errorf(err.Error())
			}
		}
	}

	// Delete any pools in the F5 not in Kubernetes

	for idx, f5pool := range f5State.Pools {
		found := false
		for _, vs := range k8sState {
			poolName := f5PoolName(vs)
			if f5pool.Name == poolName {
				found = true
				break
			}
		}
		if !found {
			if err := deletePool(idx); err != nil {
				log.Errorf(err.Error())
			}
		}
	}

	// Delete monitors

	for idx, f5monitor := range f5State.Monitors {
		found := false
		for _, vs := range k8sState {
			monitorName := f5MonitorName(vs)
			if f5monitor.Name == monitorName {
				found = true
				break
			}
		}
		if !found {
			if err := deleteMonitor(idx); err != nil {
				log.Errorf(err.Error())
			}
		}
	}

	// Nodes

	for idx, f5node := range f5State.Nodes {
		found := false
		log.Debugf(fmt.Sprintf("Assessing node %s for deletion",f5node.Name))
		for _, vs := range k8sState {
			for mIdx, _ := range vs.Members {
				nodeName := f5NodeName(vs, mIdx)
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
			log.Debugf(fmt.Sprintf("Calling delete for node %s",f5node.Name))
			if err := deleteNode(idx); err != nil {
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

	log.Debugf("Connected to F5.")

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
						"vs": virtualServer.Name,
					}).Debugf("Virtual server found.")
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
					log.WithFields(log.Fields{
						"pool":   pool.Name,
						"thread": "F5",
					}).Debugf("Pool found.")
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
				}).Debugf("Monitor found.")
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
					}).Debugf("Node found.")
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
