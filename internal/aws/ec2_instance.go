package aws_ec2

import (
	"context"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/pkg/errors"
)

type EC2Instance struct {
	instanceID       string
	instanceType     string
	availabilityZone string
	vpcID            string
	metalLbEniID     string
	interfaces       []ENIInterface
	metalLbInterface ENIInterface
	mainInterface    ENIInterface
}

const (
	EniNoManageTagKey          = "node.k8s.amazonaws.com/no_manage"
	EniNoManageTagMetalLBValue = "true"
	EniMetalLBTagKey           = "node.k8s.amazonaws.com/metallb"
	EniMetalLBTagValue         = "true"
	MaxENIs                    = 100
)

func newEC2Client() (*ec2.Client, error) {
	cfg, err := awsConfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	return ec2.NewFromConfig(cfg), nil
}

func (i *EC2Instance) GetFreeDeviceNumber() (int32, error) {
	describeInstancesOutput, err := i.DescribeInstance()

	if err != nil {
		return 0, err
	}

	if len(describeInstancesOutput.Reservations) != 1 {
		return 0, errors.Errorf("awsGetFreeDeviceNumber: invalid instance id %s", i.instanceID)
	}

	inst := describeInstancesOutput.Reservations[0].Instances[0]
	var device [MaxENIs]bool
	for _, eni := range inst.NetworkInterfaces {
		if *eni.Attachment.DeviceIndex <= MaxENIs {
			device[*eni.Attachment.DeviceIndex] = true
		}
	}

	for freeDeviceIndex := 0; freeDeviceIndex < MaxENIs; freeDeviceIndex++ {
		if !device[freeDeviceIndex] {
			return int32(freeDeviceIndex), nil
		}
	}
	return 0, errors.New("awsGetFreeDeviceNumber: no available device number")
}

func (i *EC2Instance) DescribeInstance() (*ec2.DescribeInstancesOutput, error) {
	ec2Client, err := newEC2Client()
	if err != nil {
		return nil, err
	}

	describeInstancesInput := ec2.DescribeInstancesInput{
		InstanceIds: []string{i.instanceID},
	}
	return ec2Client.DescribeInstances(context.TODO(), &describeInstancesInput)
}

func (i *EC2Instance) EnsureMetalLbENI(securityGroupID string) (metalLBEniID string, err error) {
	ec2Client, err := newEC2Client()
	if err != nil {
		return "", err
	}

	eniIf, err := GetInterfaceWithTag(i.instanceID, EniMetalLBTagKey, EniMetalLBTagValue)
	if err != nil {
		return "", err
	}

	subnetMask, err := i.mainInterface.GetSubnetMask()
	if err != nil {
		return "", err
	}

	if eniIf != nil {
		i.metalLbInterface = ENIInterface{
			MacAddress:  *eniIf.MacAddress,
			EniID:       *eniIf.NetworkInterfaceId,
			VpcID:       *eniIf.VpcId,
			SubnetID:    *eniIf.SubnetId,
			DeviceIndex: *eniIf.Attachment.DeviceIndex,
			PrivateIPs:  eniIf.PrivateIpAddresses,
			PrimaryIP:   *eniIf.PrivateIpAddress,
			SubnetMask:  subnetMask,
		}
		i.metalLbEniID = *eniIf.NetworkInterfaceId

		if securityGroupID != "" {
			modifyNetworkInterfaceAttributeInput := ec2.ModifyNetworkInterfaceAttributeInput{
				NetworkInterfaceId: eniIf.NetworkInterfaceId,
				Groups:             []string{securityGroupID},
			}
			_, err = ec2Client.ModifyNetworkInterfaceAttribute(
				context.TODO(), &modifyNetworkInterfaceAttributeInput)
			if err != nil {
				return *eniIf.NetworkInterfaceId, err
			}
		}

		return *eniIf.NetworkInterfaceId, nil
	}

	description := "Used by MetalLB to provide private IPs to LoadBalancer services."
	eniNoManageTagKeyVar := EniNoManageTagKey
	eniNoManageTagMetalLBValueVar := EniNoManageTagMetalLBValue
	eniMetalLBTagKeyVar := EniMetalLBTagKey
	eniMetalLBTagValueVar := EniMetalLBTagValue

	tagSpecifications := []types.TagSpecification{{
		ResourceType: types.ResourceTypeNetworkInterface,
		Tags: []types.Tag{
			{
				Key:   &eniNoManageTagKeyVar,
				Value: &eniNoManageTagMetalLBValueVar,
			},
			{
				Key:   &eniMetalLBTagKeyVar,
				Value: &eniMetalLBTagValueVar,
			},
		}},
	}
	createNetworkInterfaceInput := ec2.CreateNetworkInterfaceInput{
		SubnetId:          &i.mainInterface.SubnetID,
		Description:       &description,
		TagSpecifications: tagSpecifications,
		Groups:            []string{securityGroupID},
	}
	createNetworkInterfaceOutput, err := ec2Client.CreateNetworkInterface(context.TODO(), &createNetworkInterfaceInput)
	if err != nil {
		return "", err
	}

	deviceIndex, err := i.GetFreeDeviceNumber()
	if err != nil {
		cleanupENI(ec2Client, createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId)
		return "", err
	}

	attachNetworkInterfaceInput := ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        &deviceIndex,
		InstanceId:         &i.instanceID,
		NetworkInterfaceId: createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId,
	}
	attachNetworkInterfaceOutput, err := ec2Client.AttachNetworkInterface(context.TODO(), &attachNetworkInterfaceInput)
	if err != nil {
		cleanupENI(ec2Client, createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId)
		return "", err
	}

	truePtr := true
	networkInterfaceAttachmentChanges := types.NetworkInterfaceAttachmentChanges{
		AttachmentId:        attachNetworkInterfaceOutput.AttachmentId,
		DeleteOnTermination: &truePtr,
	}
	modifyNetworkInterfaceAttributeInput := ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId,
		Attachment:         &networkInterfaceAttachmentChanges,
	}
	_, err = ec2Client.ModifyNetworkInterfaceAttribute(context.TODO(), &modifyNetworkInterfaceAttributeInput)
	if err != nil {
		cleanupENI(ec2Client, createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId)
		return "", err
	}

	var emptyPrivateIpList []types.NetworkInterfacePrivateIpAddress
	i.metalLbInterface = ENIInterface{
		MacAddress:  *createNetworkInterfaceOutput.NetworkInterface.MacAddress,
		EniID:       *createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId,
		VpcID:       *createNetworkInterfaceOutput.NetworkInterface.VpcId,
		SubnetID:    *createNetworkInterfaceOutput.NetworkInterface.SubnetId,
		PrimaryIP:   *createNetworkInterfaceOutput.NetworkInterface.PrivateIpAddress,
		DeviceIndex: deviceIndex,
		PrivateIPs:  emptyPrivateIpList,
		SubnetMask:  subnetMask,
	}

	i.metalLbEniID = *createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId
	return *createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId, nil
}

func (i *EC2Instance) ConfigureMetalLbENI() error {
	mtu, err := i.mainInterface.GetMTU()
	if err != nil {
		mtu = 9001
	}
	gw, err := i.mainInterface.GetDefaultGW()
	if err != nil {
		return err
	}
	err = i.metalLbInterface.SetUP()
	if err != nil {
		return err
	}
	err = i.metalLbInterface.SetMTU(mtu)
	if err != nil {
		return err
	}
	err = i.metalLbInterface.EnableLooseRpFilter()
	if err != nil {
		return err
	}
	err = i.metalLbInterface.InitRouteTable(gw)
	if err != nil {
		return err
	}

	err = i.metalLbInterface.InitMetalLbRule(0x800)
	if err != nil {
		return err
	}

	err = i.metalLbInterface.EnsureMetalLbIptableMark(0x800)

	return nil
}

func cleanupENI(ec2Client *ec2.Client, eniID *string) {
	deleteNetworkInterfaceInput := ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: eniID,
	}
	ec2Client.DeleteNetworkInterface(context.TODO(), &deleteNetworkInterfaceInput)
}

func (i *EC2Instance) AttachPrivateIP(privateIpAddr string) (err error) {
	ec2Client, err := newEC2Client()
	if err != nil {
		return err
	}

	interfaceStatus, err := GetInterfaceWithEniID(i.metalLbEniID)
	if err != nil {
		return err
	}

	privateIPList := []string{privateIpAddr}
	for _, ipStruct := range interfaceStatus.PrivateIpAddresses {
		if privateIpAddr == *ipStruct.PrivateIpAddress {
			// Already attached to this ENI
			return
		}

		privateIPList = append(privateIPList, *ipStruct.PrivateIpAddress)
	}

	allowReassignment := true
	assignPrivateIpAddressesInput := ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             interfaceStatus.NetworkInterfaceId,
		AllowReassignment:              &allowReassignment,
		Ipv4PrefixCount:                nil,
		Ipv4Prefixes:                   nil,
		PrivateIpAddresses:             privateIPList,
		SecondaryPrivateIpAddressCount: nil,
	}

	_, err = ec2Client.AssignPrivateIpAddresses(context.TODO(), &assignPrivateIpAddressesInput)
	if err != nil {
		return err
	}

	return
}
