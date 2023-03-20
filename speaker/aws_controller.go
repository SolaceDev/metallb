// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	ec2_metadata "go.universe.tf/metallb/internal/aws"
	"net"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"go.universe.tf/metallb/internal/config"
	"go.universe.tf/metallb/internal/k8s/epslices"

	v1 "k8s.io/api/core/v1"
)

type awsController struct {
	myNode           string
	localEC2Instance ec2_metadata.EC2Instance
	metalLBEniID     string
	securityGroupID  string
}

func (c *awsController) SetConfig(l log.Logger, config *config.Config) error {
	ec2Metadata, err := ec2_metadata.GetInstanceMetadata()

	if err != nil {
		return err
	}

	c.localEC2Instance = ec2Metadata

	c.metalLBEniID, err = c.localEC2Instance.EnsureMetalLbENI(c.securityGroupID)
	if err != nil {
		return err
	}
	err = c.localEC2Instance.ConfigureMetalLbENI()
	if err != nil {
		return err
	}

	return nil
}

func (c *awsController) ShouldAnnounce(l log.Logger, name string, toAnnounce []net.IP, pool *config.Pool, svc *v1.Service, eps epslices.EpsOrSlices) string {
	activeEndpointExists, activeEndpointIP := getActiveLocalEndpointIP(eps, c.myNode)

	if !activeEndpointExists { // no active endpoints, just return
		level.Debug(l).Log("event", "shouldannounce", "protocol", "l2", "message", "failed no active endpoints", "service", name)
		return "notOwner"
	}

	if !poolMatchesNodeAWS(pool, c.myNode) {
		level.Debug(l).Log("event", "skipping should announce l2", "service", name, "reason", "pool not matching my node")
		return "notOwner"
	}

	// we select the nodes with at least one matching l2 advertisement
	// Using the first IP should work for both single and dual stack.
	ipString := toAnnounce[0].String()
	level.Info(l).Log("event", "Attaching Load Balancer IP ", ipString, " to endpoint ", activeEndpointIP)

	err := c.localEC2Instance.AttachPrivateIP(ipString)
	if err != nil {
		level.Error(l).Log("event", "Failed to attach "+ipString+" to "+activeEndpointIP, "reason", err)
		return "notOwner"
	}

	return ""
}

func (c *awsController) SetBalancer(l log.Logger, name string, lbIPs []net.IP, pool *config.Pool, client service, svc *v1.Service) error {
	level.Warn(l).Log("SetBalancer, no clue what to do with name: ", name, " IPs:", lbIPs)
	return nil
}

func (c *awsController) DeleteBalancer(l log.Logger, name, reason string) error {
	level.Warn(l).Log("DeleteBalancer", name, reason)

	return nil
}

func (c *awsController) SetNode(l log.Logger, node *v1.Node) error {
	level.Warn(l).Log("SetNode", *node)

	return nil
}

// Returns true if at least one endpoint is active and the first endpoint's IP.
func getActiveLocalEndpointIP(eps epslices.EpsOrSlices, localNode string) (bool, string) {
	switch eps.Type {
	case epslices.Eps:
		for _, subset := range eps.EpVal.Subsets {
			if len(subset.Addresses) > 0 {
				return true, subset.Addresses[0].IP
			}
		}
	case epslices.Slices:
		for _, slice := range eps.SlicesVal {
			for _, ep := range slice.Endpoints {
				if *ep.NodeName != localNode {
					continue
				}
				if !epslices.IsConditionReady(ep.Conditions) {
					continue
				}
				return true, ep.Addresses[0]
			}
		}
	}
	return false, ""
}

func poolMatchesNodeAWS(pool *config.Pool, node string) bool {
	for _, adv := range pool.AWSAdvertisements {
		if adv.Nodes[node] {
			return true
		}
	}
	return false
}
