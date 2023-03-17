package aws_ec2

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.universe.tf/metallb/internal/aws/procsyswrapper"
	"golang.org/x/sys/unix"
	"net"
	"syscall"
	"time"
)

type ENIInterface struct {
	MacAddress  string
	EniID       string
	VpcID       string
	SubnetID    string
	DeviceIndex int32
	PrimaryIP   string
	SubnetMask  net.IPMask
	PrivateIPs  []types.NetworkInterfacePrivateIpAddress
}

func (i *ENIInterface) GetPrivateIPCount() (l int) {
	l = len(i.PrivateIPs)

	return
}

func (i *ENIInterface) GetPrivateIPList() (privateIPs []string) {
	for _, eniIf := range i.PrivateIPs {
		privateIPs = append(privateIPs, *eniIf.PrivateIpAddress)
	}

	return
}

func (i *ENIInterface) GetLinuxIfName() (string, error) {
	var linuxIfName string

	link, err := i.GetLinuxIf()

	if err != nil {
		return linuxIfName, errors.Wrap(err, "Failed to list links")
	}

	linuxIfName = link.Attrs().Name

	return linuxIfName, nil
}

func (i *ENIInterface) GetLinuxIf() (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list links")
	}
	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == i.MacAddress {
			return link, nil
		}
	}

	return nil, errors.New("Couldn't find ENI interface in linux link list.")
}

func (i *ENIInterface) EnableLooseRpFilter() error {
	linuxIfName, err := i.GetLinuxIfName()
	if err != nil {
		return err
	}

	procSys := procsyswrapper.NewProcSys()
	// Configure rp_filter in loose mode
	entry := "net/ipv4/conf/" + linuxIfName + "/rp_filter"
	err = procSys.Set(entry, "2")
	if err != nil {
		return errors.Wrapf(err, "Failed to set rp_filter for %s", linuxIfName)
	}

	return nil
}

const retryInterval = 3 * time.Second
const maxAttempts = 5

func (i *ENIInterface) SetUP() error {
	var err error
	var link netlink.Link
	attempt := 0

	for {
		link, err = i.GetLinuxIf()
		if err != nil {
			if attempt < maxAttempts {
				time.Sleep(retryInterval)
				attempt++
				continue
			} else {
				return err
			}
		}
		break
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return errors.Wrap(err, "setupENINetwork: failed to list IP address for ENI")
	}

	for _, addr := range addrs {
		if err = netlink.AddrDel(link, &addr); err != nil {
			return errors.Wrap(err, "setupENINetwork: failed to delete IP addr from ENI")
		}
	}
	eniAddr := &net.IPNet{
		IP:   net.ParseIP(i.PrimaryIP),
		Mask: i.SubnetMask,
	}
	if err = netlink.AddrAdd(link, &netlink.Addr{IPNet: eniAddr}); err != nil {
		return errors.Wrap(err, "setupENINetwork: failed to add IP addr to ENI")
	}
	return nil
}

func (i *ENIInterface) GetMTU() (int, error) {
	link, err := i.GetLinuxIf()
	if err != nil {
		return 0, err
	}
	return link.Attrs().MTU, nil
}

func (i *ENIInterface) SetMTU(mtu int) error {
	link, err := i.GetLinuxIf()
	if err != nil {
		return err
	}

	netlink.LinkSetMTU(link, mtu)
	return nil
}

func (i *ENIInterface) GetNetwork() (*net.IPNet, error) {
	link, err := i.GetLinuxIf()
	if err != nil {
		return nil, err
	}

	addresses, err := netlink.AddrList(link, unix.AF_INET)

	return addresses[0].IPNet, err
}

func (i *ENIInterface) GetSubnetMask() (net.IPMask, error) {
	ipNet, err := i.GetNetwork()
	if err != nil {
		return nil, err
	}

	return ipNet.Mask, nil
}

func (i *ENIInterface) GetDefaultGW() (net.IP, error) {
	link, err := i.GetLinuxIf()
	if err != nil {
		return nil, err
	}
	routes, err := netlink.RouteList(link, unix.AF_INET)
	if err != nil {
		return nil, err
	}

	for _, route := range routes {
		if route.Dst == nil {
			return route.Gw, nil
		}
	}

	return nil, errors.New("Default gateway not found for " + link.Attrs().Name)
}

func (i *ENIInterface) GetRouteTableNumber() (int, error) {
	link, err := i.GetLinuxIf()
	if err != nil {
		return 0, err
	}
	linkIndex := link.Attrs().Index
	return linkIndex + 1, nil
}

type iptablesRule struct {
	name         string
	table, chain string
	rule         []string
}

func (i *ENIInterface) EnsureMetalLbIptableMark(metalLbMark int32) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return err
	}

	metalLbIntfName, err := i.GetLinuxIfName()
	if err != nil {
		return err
	}

	var iptableRules []iptablesRule
	iptableRules = append(iptableRules, iptablesRule{
		name:  "connmark for MetalLB ENI",
		table: "mangle",
		chain: "PREROUTING",
		rule: []string{
			"-m", "comment", "--comment", "MetalLB, Mark connections made via MetalLB ENI so that they match a rule that routes back out that same MetalLB ENI.",
			"-i", metalLbIntfName,
			"-j", "CONNMARK", "--set-mark", fmt.Sprintf("%#x/%#x", metalLbMark, metalLbMark),
		},
	})
	iptableRules = append(iptableRules, iptablesRule{
		name:  "connmark restore for primary ENI",
		table: "mangle",
		chain: "PREROUTING",
		rule: []string{
			"-m", "comment", "--comment", "MetalLB, Restore the MetalLB marks so packets for metallb connections gets routed out via the MetalLB ENI.",
			"-i", "eni+", "-j", "CONNMARK", "--restore-mark", "--mask", fmt.Sprintf("%#x", metalLbMark),
		},
	})

	for _, rule := range iptableRules {
		exists, err := ipt.Exists(rule.table, rule.chain, rule.rule...)
		if err != nil {
			return err
		}

		if !exists {
			err = ipt.Append(rule.table, rule.chain, rule.rule...)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (i *ENIInterface) InitMetalLbRule(metalLbMark int32) error {
	linkIndex, err := i.GetRouteTableNumber()
	if err != nil {
		return err
	}

	metalLbRule := netlink.NewRule()
	metalLbRule.Mark = int(metalLbMark)
	metalLbRule.Mask = int(metalLbMark)
	metalLbRule.Table = linkIndex
	metalLbRule.Priority = 1024
	metalLbRule.Family = unix.AF_INET

	// If this is a restart, cleanup previous rule first
	err = netlink.RuleDel(metalLbRule)
	if err != nil && !containsNoSuchRule(err) {
		return errors.Wrapf(err, "host network setup: failed to delete old main ENI rule")
	}
	err = netlink.RuleAdd(metalLbRule)
	if err != nil {
		return errors.Wrapf(err, "host network setup: failed to add main ENI rule")
	}

	return nil
}

func containsNoSuchRule(err error) bool {
	if errno, ok := err.(syscall.Errno); ok {
		return errno == syscall.ENOENT
	}
	return false
}

func (i *ENIInterface) InitRouteTable(gw net.IP) error {
	link, err := i.GetLinuxIf()
	if err != nil {
		return err
	}

	existingRoutes, err := netlink.RouteList(link, unix.AF_INET)
	if len(existingRoutes) == 2 {
		return nil
	}

	linkIndex := link.Attrs().Index
	tableNumber := linkIndex + 1

	routes := []netlink.Route{
		// Add a direct link route for the host's ENI IP only
		{
			LinkIndex: linkIndex,
			Dst:       &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)},
			Scope:     netlink.SCOPE_LINK,
			Table:     tableNumber,
		},
		// Route all other traffic via the host's ENI IP
		{
			LinkIndex: linkIndex,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Scope:     netlink.SCOPE_UNIVERSE,
			Gw:        gw,
			Table:     tableNumber,
		},
	}
	for _, r := range routes {
		err = netlink.RouteAdd(&r)

		if err != nil && err != syscall.EEXIST {
			return err
		}
	}
	return nil
}

func GetInterfaceWithTag(instanceID string, tagKey string, tagValue string) (eniInterface *types.NetworkInterface, err error) {
	ec2Client, err := newEC2Client()
	if err != nil {
		return nil, err
	}

	tagFilter := "tag:" + tagKey
	instanceIDFilter := "attachment.instance-id"
	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   &tagFilter,
				Values: []string{tagValue},
			},
			{
				Name:   &instanceIDFilter,
				Values: []string{instanceID},
			},
		},
	}

	describeNetworkInterfacesOutput, err := ec2Client.DescribeNetworkInterfaces(context.TODO(), &describeNetworkInterfacesInput)
	if err != nil {
		return nil, err
	}
	if len(describeNetworkInterfacesOutput.NetworkInterfaces) > 0 {
		return &describeNetworkInterfacesOutput.NetworkInterfaces[0], nil
	}

	return nil, nil
}

func GetInterfaceWithEniID(eniID string) (eniInterface *types.NetworkInterface, err error) {
	ec2Client, err := newEC2Client()
	if err != nil {
		return nil, err
	}

	eniIDFilter := "network-interface-id"
	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   &eniIDFilter,
				Values: []string{eniID},
			},
		},
	}

	describeNetworkInterfacesOutput, err := ec2Client.DescribeNetworkInterfaces(context.TODO(), &describeNetworkInterfacesInput)
	if err != nil {
		return nil, err
	}
	networkIf := describeNetworkInterfacesOutput.NetworkInterfaces[0]

	return &networkIf, nil
}
