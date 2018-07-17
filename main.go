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

type LTMState struct {
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

func applyF5Diffs(k8sState KubernetesState, f5State LTMState) error {

	// Step through virtual servers, creating as necessary

	metadata := bigip.Metadata{
		Name:    "f5-ingress-ctlr-managed",
		Value:   "true",
		Persist: "true",
	}

	description := "Managed by Kubernetes. Please do not make manual changes."

	// Delete any virtual servers that are in the F5, but no longer in Kubernetes.

	for _, f5vs := range f5State.Virtuals {
		found := false
		for _, vs := range k8sState {
			vsName := f5VirtualServerName(vs)
			if f5vs.Name == vsName {
				found = true
				break
			}
		}
		if !found {
			// Delete the server on the F5
			log.Debugf(fmt.Sprintf("Remove the virtual server %s", f5vs.FullPath))
			err := f5.DeleteVirtualServer(f5vs.FullPath)
			if err != nil {
				log.Errorf("Error removing virtual server")
			}
		}
	}

	// Delete any pools in the F5 not in Kubernetes

	for _, f5pool := range f5State.Pools {
		found := false
		for _, vs := range k8sState {
			poolName := f5PoolName(vs)
			if f5pool.Name == poolName {
				found = true
				break
			}
		}
		if !found {
			// Delete the pool on the F5
			log.Debugf(fmt.Sprintf("Remove the pool %s", f5pool.FullPath))
			err := f5.DeletePool(f5pool.FullPath)
			if err != nil {
				log.Errorf("Error removing pool")
			}
		}
	}

	// Delete monitors

	for _, f5monitor := range f5State.Monitors {
		found := false
		for _, vs := range k8sState {
			monitorName := f5MonitorName(vs)
			if f5monitor.Name == monitorName {
				found = true
				break
			}
		}
		if !found {
			// Delete the monitor on the F5
			log.Debugf(fmt.Sprintf("Remove the %s monitor %s", f5monitor.MonitorType, f5monitor.FullPath))
			err := f5.DeleteMonitor(f5monitor.FullPath, f5monitor.MonitorType)
			if err != nil {
				log.Errorf("Error removing monitor")
			}
		}
	}

	// Nodes

	for _, f5node := range f5State.Nodes {
		found := false
		var vs KsVirtualServer

		for _, vs = range k8sState {
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

			// Remove the node from the associated pool
			poolName := "/" + globalConfig.Partition + "/" + f5PoolName(vs)
			// First check if it's in the pool, or even if the pool exists
			log.Debugf(fmt.Sprintf("Remove the node %s from pool %s", f5node.Name, poolName))
			poolMember := &bigip.PoolMember{
				FullPath:  f5node.FullPath,
				Name:      f5node.Name,
				Partition: globalConfig.Partition,
			}
			if err := f5.RemovePoolMember(poolName,poolMember); err != nil {
				log.Debugf(fmt.Sprintf("Member not removed from pool, this is safe to ignore"))
				log.Debugf(err.Error())
			}
			// Delete the node on the F5
			log.Debugf(fmt.Sprintf("Remove the node %s", f5node.FullPath))
			err := f5.DeleteNode(f5node.FullPath)
			if err != nil {
				log.Errorf("Error removing node")
				log.Debugf(err.Error())
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

func buildCurrentLTMState() (LTMState, error) {

	var cs LTMState

	var f5_user, f5_password, f5_host string

	var err error

	if f5_user = os.Getenv("F5_USER"); f5_user == "" {
		return cs, fmt.Errorf("F5_USER environment variable must be set")
	}

	if f5_password = os.Getenv("F5_PASSWORD"); f5_password == "" {
		return cs, fmt.Errorf("F5_PASSWORD environment variable must be set")
	}

	if f5_host = os.Getenv("F5_HOST"); f5_host == "" {
		return cs, fmt.Errorf("F5_HOST environment variable must be set")
	}

	f5, err = bigip.NewTokenSession(f5_host, f5_user, f5_password, "tmos", &bigip.ConfigOptions{})

	if err != nil {
		log.Debugf("Failed to get token")
		return cs, err
	}

	log.Debugf("Connected to F5")

	virtualServers, err := f5.VirtualServersForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 virtual server information")
		return cs, err
	}

	pools, err := f5.PoolsForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 pool information")
		return cs, err
	}

	monitors, err := f5.MonitorsForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 monitor information")
		return cs, err
	}

	nodes, err := f5.NodesForPartition(globalConfig.Partition)
	if err != nil {
		log.Debugf("Failed to retrieve F5 node information")
		return cs, err
	}

	// Clean the virtual server list - only copy over virtual server
	// entries that are in our specified partition, and have a
	// metadata entry of "f5-ingress-ctlr-managed" set to "true"

	for _, virtualServer := range virtualServers.VirtualServers {
		log.WithFields(log.Fields{
			"name":      virtualServer.Name,
			"partition": virtualServer.Partition,
		}).Debugf("Assessing virtual server")
		if virtualServer.Partition == globalConfig.Partition {
			for _, metadata := range virtualServer.Metadata {
				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
					log.WithFields(log.Fields{
						"name":      virtualServer.Name,
						"partition": virtualServer.Partition,
					}).Debugf("Virtual server is in specified partition and is managed by this module")
					cs.Virtuals = append(cs.Virtuals, virtualServer)
					break
				}
			}
		}
	}

	// Same with pools

	for _, pool := range pools.Pools {
		log.WithFields(log.Fields{
			"name":      pool.Name,
			"partition": pool.Partition,
		}).Debugf("Assessing pool")
		if pool.Partition == globalConfig.Partition {
			for _, metadata := range pool.Metadata {
				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
					log.WithFields(log.Fields{
						"name":      pool.Name,
						"partition": pool.Partition,
					}).Debugf("Pool is in specified partition and is managed by this module")
					cs.Pools = append(cs.Pools, pool)
					break
				}
			}
		}
	}

	// Same with monitors

	for _, monitor := range monitors {
		log.WithFields(log.Fields{
			"name":      monitor.Name,
			"partition": monitor.Partition,
		}).Debugf("Assessing monitor")
		if monitor.Partition == globalConfig.Partition {
			log.Debugf("Partition in monitor is correct")
			if monitor.Description == "Managed by Kubernetes. Please do not make manual changes." {
				//			for _, metadata := range monitor.Metadata {
				//				log.Debugf(fmt.Sprintf("Metadata.Name is %s", metadata.Name))
				//				log.Debugf(fmt.Sprintf("Metadata.Value is %s", metadata.Value))
				//				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
				log.WithFields(log.Fields{
					"name":      monitor.Name,
					"partition": monitor.Partition,
				}).Debugf("Monitor is in specified partition and is managed by this module")
				cs.Monitors = append(cs.Monitors, monitor)
				//					break
				//				}
			}
		}
	}

	// Finally, same with nodes

	for _, node := range nodes.Nodes {
		log.WithFields(log.Fields{
			"name":      node.Name,
			"partition": node.Partition,
		}).Debugf("Assessing node")
		if node.Partition == globalConfig.Partition {
			for _, metadata := range node.Metadata {
				if metadata.Name == "f5-ingress-ctlr-managed" && metadata.Value == "true" {
					log.WithFields(log.Fields{
						"name":      node.Name,
						"partition": node.Partition,
					}).Debugf("Node is in specified partition and is managed by this module")
					cs.Nodes = append(cs.Nodes, node)
					break
				}
			}
		}
	}

	return cs, nil
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

func main() {

	// initialize the Kubernetes connection

	log.SetLevel(log.DebugLevel)

	err := initKubernetes()
	if err != nil || clientset == nil {
		log.Error("Could not initialize a connection to Kubernetes")
		log.Error(err.Error())
		os.Exit(1)
	}

	globalConfig.Partition = "k8s-auto-ny2"

	for true {
		desiredState, err := getKubernetesState()
		if err != nil {
			log.Error("Could not fetch desired state from Kubernetes")
			log.Error(err.Error())
			os.Exit(1)
		}

		//		desiredJson, _ := json.MarshalIndent(desiredState, "", "  ")
		//		fmt.Printf(string(desiredJson))

		currentState, err := buildCurrentLTMState()
		if err != nil {
			log.Error("Could not fetch current state from F5")
			log.Error(err.Error())
			os.Exit(1)
		}

		//		currentJson, _ := json.MarshalIndent(currentState, "", "  ")
		//		fmt.Printf(string(currentJson))

		err = applyF5Diffs(desiredState, currentState)
		if err != nil {
			log.Error("Could not apply Kubernetes state to F5")
			log.Error(err.Error())
			os.Exit(1)
		}
		time.Sleep(15 * time.Second)
	}
}
