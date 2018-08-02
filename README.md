[![Build Status](https://travis-ci.org/mzahorik/f5-ingress-ctlr.svg?branch=master)](https://travis-ci.org/mzahorik/f5-ingress-ctlr) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
# F5-ingress-ctlr
A Kubernetes Ingress controller for the BIG-IP appliances

# Introduction

This controller synchronizes Kubernetes Ingress objects and a F5 BIG-IP controller.

It was spawned out of frustration with the complexity and bugs present in the F5-supplied k8s-bigip-ctlr and f5-ipam-ctlr.  This is designed as a slimmed down version focusing solely on Ingress objects - no configmap JSON configs, no openshift, etc.

While not a drop in replacement for the F5-supplied k8s-bigip-ctlr, many of the annotations are used unchanged.

This code is considered Alpha state.  I've only just begun testing, and while functionally correct, it's not elegant by any means.

# Installation

This controller is only delivered as a Docker container.  The latest can be found at https://hub.docker.com/r/mzahorik/f5-ingress-ctlr/

The controller assumes that POD IPs are directly routable by the F5 without NAT.  For on-prem Kubernetes deploys, the author uses Calico in L3/BGP mode with NAT.  Cloud offerings such as Azure's and AWS' Kubernetes services offer something similar.  Support for NodePort type services is a future enhancement that may never be satisfied.

A sample Kubernetes YAML file can be found in deploy/k8s.  Modify the following environment variables:

Variable | Description | Sample Value
-------- | ----------- | ------------
BIGIP_HOST | The DNS name/IP address of the F5 BIG-IP iControl REST API.  This field is required. | 192.168.1.1
BIGIP_PARTITION | The administrative partition on the BIG-IP device.  This field is required. | kubernetes
DEBUG | Logs will contain detailed debugging information.  Any value can be used, the environment variable only needs to exist. Optional. | true
F5_ROUTE_DOMAIN | The numeric route domain for the virtual IP subnet on the BIG-IP. This will be automatically detected, and this environment variable deprecated, in a future release  | 123
INFOBLOX_SUBNET | The subnet, in CIDR notation, that the controller will allocate addresses from.  If omitted, the Infoblox integration will be disabled | 10.1.123.1/24
INFOBLOX_HOST | The DNS name/IP address of the Infoblox API. If omitted, the Infoblox integration will be disabled | 192.168.1.100
K8S_POLL_INTERVAL | Number of seconds between queries to Kubernetes to get full list of ingresses and pods.  This will be deprecated in a future release of the code.  If omitted, the controller defaults to 15 seconds. | 5
REFRESH_INTERVAL | After REFRESH_INTERVAL minutes the controller will discard it's internal state and get a full list of objects from the BIG-IP, Infoblox, and Kubernetes.  If omitted, the controller defaults to 15 minutes | 30

and then:

```
kubectl create secret generic f5-ingress-ctlr-creds --from-literal=f5_user=<your F5 username> --from-literal=f5_pass=<your F5 password>
kubectl apply -f deploy/k8s/sample-deployment -n <your namespace if not default>
```

if you're using the Infoblox integration, add in the Infoblox credentials:

```
kubectl create secret generic f5-ingress-ctlr-creds --from-literal=f5_user=<your F5 username> --from-literal=f5_pass=<your F5 password> --from-literal=infoblox_user=<your Infoblox username> --from-literal=infoblox_pass=<your Infoblox password>
kubectl apply -f deploy/k8s/sample-deployment -n <your namespace if not default>
```

# Usage

Once deployed and running, the Ingress controller will monitor Kubernetes for the addition, change, or removal of Ingress objects.  It will attempt to replicate the Ingress configuration on the BIG-IP appliance.

The Ingress controller accepts the following annotations:

Annotations | Default Value | Valid Values | Sample Value
----------- | ------------- | ------------ | ------------
infoblox-ipam/hostname | none | any valid DNS name | www.domain.com
infoblox-ipam/ip-allocation | none | dynamic | dynamic

These annotations control the Infoblox IP address allocation on a per-Ingress basis.  Both annotations must be set, otherwise they are both ignored.  If these annotations are unset, see virtual-server.f5.com/ip.

If these annotations exist, upon creating a virtual server on the BIG-IP, an Infoblox host record will be created on the next available IP in the subnet specified by the F5_VIP_CIDR environment variable.  Once the virtual server on the BIG-IP is removed, through removal of the Ingress object in Kubernetes, the host entry in the Infoblox will be removed.

A custom attribute named "F5-IPAM" must be present on the Infoblox. This can be set under Administration -> Extensible Attributes.  The controller will only add records with "F5-IPAM" set to "true", and will only delete records within the F5_VIP_CIDR subnet with "F5-IPAM" set to "true".

To be documented:

Annotations | Default Value | Valid Values | Sample Value
----------- | ------------- | ------------ | ------------
virtual-server.f5.com/balance | none | https://support.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-concepts-11-4-0/5.html | round-robin
virtual-server.f5.com/defaultPersist | none | A valid pre-configured persistence profile | /Common/ssl
virtual-server.f5.com/fallbackPersist | none | A valid pre-configured persistence profile | /Common/source_addr
virtual-server.f5.com/health | na | na | na
virtual-server.f5.com/http-port | na | na | na
virtual-server.f5.com/https-port | na | na | na
virtual-server.f5.com/ip | na | na | na
virtual-server.f5.com/rules | na | na | na
virtual-server.f5.com/serverssl | na | na | na
virtual-server.f5.com/ssl-redirect | na | na | na

# Copyright

Copyright (c) 2018, Matt Zahorik <matt.zahorik@gmail.com>

# License

## Apache V2.0

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations
under the License.
