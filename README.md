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
F5_HOST | The DNS name/IP address where the F5 BIG-IP answers iControl REST calls | 192.168.1.1
F5_ROUTE_DOMAIN | The numeric route domain for the virtual IP subnet on the BIG-IP. This will be automatically detected and deprecated in a future release  | 123
F5_VIP_CIDR | The subnet on the F5 where virtual IP addresses reside | 10.1.123.1/24
INFOBLOX_HOST | The DNS name/IP address for the Infoblox API. If omitted, the Infoblox integration will be disabled | 192.168.1.100

and then:

`kubectl create secret generic f5-ingress-ctlr-creds --from-literal=f5_user=<your F5 username> --from-literal=f5_pass=<your F5 password>
kubectl apply -f deploy/k8s/sample-deployment -n <your namespace if not default>`

if using the Infoblox integration, add in the Infoblox credentials:

`kubectl create secret generic f5-ingress-ctlr-creds --from-literal=f5_user=<your F5 username> --from-literal=f5_pass=<your F5 password> --from-literal=infoblox_user=<your Infoblox username> --from-literal=infoblox_pass=<your Infoblox password>
kubectl apply -f deploy/k8s/sample-deployment -n <your namespace if not default>`

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

virtual-server.f5.com/balance
virtual-server.f5.com/defaultPersist
virtual-server.f5.com/fallbackPersist
virtual-server.f5.com/health
virtual-server.f5.com/http-port
virtual-server.f5.com/https-port
virtual-server.f5.com/ip
virtual-server.f5.com/rules
virtual-server.f5.com/serverssl
virtual-server.f5.com/ssl-redirect

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
