package aws_ec2

import (
	"context"
	"fmt"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"io"
	"strings"
)

func newClient() (*imds.Client, error) {
	cfg, err := awsConfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	return imds.NewFromConfig(cfg), nil
}

func getMetadata(client *imds.Client, path string) (string, error) {
	res, err := client.GetMetadata(context.TODO(), &imds.GetMetadataInput{
		Path: path,
	})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve AWS metadata %s: %w", path, err)
	}

	defer res.Content.Close()

	limit := 1024*1024 + 1
	buf, err := io.ReadAll(io.LimitReader(res.Content, int64(limit)))
	if err != nil {
		return string(buf), err
	}
	if len(buf) >= limit {
		return string(buf[:limit-1]), fmt.Errorf("unable to retrieve AWS metadata.  Metadata exceeds 1MB limit.")
	}
	return string(buf), nil
}

// GetInstanceMetadata returns required AWS metadatas
func GetInstanceMetadata() (ec2Metadata EC2Instance, err error) {
	client, err := newClient()
	if err != nil {
		return
	}

	ec2Metadata.instanceID, err = getMetadata(client, "instance-id")
	if err != nil {
		return
	}

	ec2Metadata.instanceType, err = getMetadata(client, "instance-type")
	if err != nil {
		return
	}

	eth0MAC, err := getMetadata(client, "mac")
	if err != nil {
		return
	}
	vpcIDPath := fmt.Sprintf("network/interfaces/macs/%s/vpc-id", eth0MAC)
	ec2Metadata.vpcID, err = getMetadata(client, vpcIDPath)
	if err != nil {
		return
	}

	interfacesString, err := getMetadata(client, "network/interfaces/macs")
	if err != nil {
		return
	}
	interfacesString = strings.ReplaceAll(interfacesString, "/", "")
	interfaceMacs := strings.Split(interfacesString, "\n")

	for _, interfaceMac := range interfaceMacs {
		var vpcID string
		vpcIDPath := fmt.Sprintf("network/interfaces/macs/%s/vpc-id", interfaceMac)
		vpcID, err = getMetadata(client, vpcIDPath)
		if err != nil {
			return
		}

		var eniID string
		eniIDPath := fmt.Sprintf("network/interfaces/macs/%s/interface-id", interfaceMac)
		eniID, err = getMetadata(client, eniIDPath)
		if err != nil {
			return
		}

		var subnetID string
		subnetIDPath := fmt.Sprintf("network/interfaces/macs/%s/subnet-id", interfaceMac)
		subnetID, err = getMetadata(client, subnetIDPath)
		if err != nil {
			return
		}

		var ipAddressesString string
		privateIpsPath := fmt.Sprintf("network/interfaces/macs/%s/local-ipv4s", interfaceMac)
		ipAddressesString, err = getMetadata(client, privateIpsPath)
		privateIPs := strings.Split(ipAddressesString, "\n")
		var netIfPrivateIps []types.NetworkInterfacePrivateIpAddress
		for _, privateIP := range privateIPs {
			netIfPrivateIps = append(netIfPrivateIps, types.NetworkInterfacePrivateIpAddress{
				Association:      nil,
				Primary:          nil,
				PrivateDnsName:   nil,
				PrivateIpAddress: &privateIP,
			})
		}
		netIf := ENIInterface{
			MacAddress: interfaceMac,
			EniID:      eniID,
			VpcID:      vpcID,
			SubnetID:   subnetID,
			PrivateIPs: netIfPrivateIps,
		}
		ec2Metadata.interfaces = append(ec2Metadata.interfaces, netIf)
		if eth0MAC == interfaceMac {
			ec2Metadata.mainInterface = netIf
		}
	}

	ec2Metadata.availabilityZone, err = getMetadata(client, "placement/availability-zone")
	if err != nil {
		return
	}

	return
}
