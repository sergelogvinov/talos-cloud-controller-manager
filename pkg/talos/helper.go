package talos

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	csr "github.com/siderolabs/talos-cloud-controller-manager/pkg/certificatesigningrequest"
	"github.com/siderolabs/talos-cloud-controller-manager/pkg/transformer"
	utilsnet "github.com/siderolabs/talos-cloud-controller-manager/pkg/utils/net"
	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/nethelpers"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"

	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	clientkubernetes "k8s.io/client-go/kubernetes"
	cloudnodeutil "k8s.io/cloud-provider/node/helpers"
)

func ipDiscovery(nodeIPs []string, ifaces []network.AddressStatusSpec) (publicIPv4s, publicIPv6s []string) {
	for _, iface := range ifaces {
		if iface.LinkName == constants.KubeSpanLinkName ||
			iface.LinkName == constants.SideroLinkName ||
			iface.LinkName == "lo" ||
			iface.LinkName == "cilium_host" ||
			strings.HasPrefix(iface.LinkName, "dummy") {
			continue
		}

		ip := iface.Address.Addr()
		if ip.IsGlobalUnicast() && !ip.IsPrivate() {
			if slices.Contains(nodeIPs, ip.String()) {
				continue
			}

			if ip.Is6() {
				// Prioritize permanent IPv6 addresses
				if nethelpers.AddressFlag(iface.Flags)&nethelpers.AddressPermanent != 0 {
					publicIPv6s = append([]string{ip.String()}, publicIPv6s...)
				} else {
					publicIPv6s = append(publicIPv6s, ip.String())
				}
			} else {
				publicIPv4s = append(publicIPv4s, ip.String())
			}
		}
	}

	return publicIPv4s, publicIPv6s
}

func getNodeAddresses(config *cloudConfig, platform string, features *transformer.NodeFeaturesFlagSpec, nodeIPs []string, ifaces []network.AddressStatusSpec) []v1.NodeAddress {
	var publicIPv4s, publicIPv6s, publicIPs []string

	switch platform {
	// Those platforms don't expose public IPs information in metadata
	case "nocloud", "metal", "openstack", "oracle": // nolint:goconst
		publicIPv4s, publicIPv6s = ipDiscovery(nodeIPs, ifaces)
	default:
		for _, iface := range ifaces {
			if iface.LinkName == "external" { // nolint:goconst
				ip := iface.Address.Addr()

				if slices.Contains(nodeIPs, ip.String()) {
					continue
				}

				if ip.Is6() {
					publicIPv6s = append(publicIPv6s, ip.String())
				} else {
					publicIPv4s = append(publicIPv4s, ip.String())
				}
			}
		}
	}

	if features != nil && features.PublicIPDiscovery {
		ipv4, ipv6 := ipDiscovery(nodeIPs, ifaces)
		publicIPv4s = append(publicIPv4s, ipv4...)
		publicIPv6s = append(publicIPv6s, ipv6...)
	}

	addresses := make([]v1.NodeAddress, 0, len(nodeIPs))
	for _, ip := range utilsnet.PreferredDualStackNodeIPs(config.Global.PreferIPv6, nodeIPs) {
		addresses = append(addresses, v1.NodeAddress{Type: v1.NodeInternalIP, Address: ip})
	}

	publicIPs = utilsnet.PreferredDualStackNodeIPs(config.Global.PreferIPv6, append(publicIPv4s, publicIPv6s...))
	for _, ip := range publicIPs {
		addresses = append(addresses, v1.NodeAddress{Type: v1.NodeExternalIP, Address: ip})
	}

	return addresses
}

func syncNodeAnnotations(ctx context.Context, c *client, node *v1.Node, nodeAnnotations map[string]string) error {
	nodeAnnotationsOrig := node.ObjectMeta.Annotations
	annotationsToUpdate := map[string]string{}

	for k, v := range nodeAnnotations {
		if r, ok := nodeAnnotationsOrig[k]; !ok || r != v {
			annotationsToUpdate[k] = v
		}
	}

	if len(annotationsToUpdate) > 0 {
		oldData, err := json.Marshal(node)
		if err != nil {
			return fmt.Errorf("failed to marshal the existing node %#v: %w", node, err)
		}

		newNode := node.DeepCopy()
		if newNode.Annotations == nil {
			newNode.Annotations = make(map[string]string)
		}

		maps.Copy(newNode.Annotations, annotationsToUpdate)

		newData, err := json.Marshal(newNode)
		if err != nil {
			return fmt.Errorf("failed to marshal the new node %#v: %w", newNode, err)
		}

		patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, &v1.Node{})
		if err != nil {
			return fmt.Errorf("failed to create a two-way merge patch: %v", err)
		}

		if _, err := c.kclient.CoreV1().Nodes().Patch(ctx, node.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("failed to patch the node: %v", err)
		}
	}

	return nil
}

func syncNodeTaints(_ context.Context, c *client, node *v1.Node, nodeTaints map[string]string) error {
	taints := make([]*v1.Taint, 0, len(nodeTaints))

	for k, v := range nodeTaints {
		taint := v1.Taint{
			Key: k,
		}

		value := strings.Split(v, ":")
		if len(value) == 2 {
			taint.Value = value[0]
			taint.Effect = v1.TaintEffect(value[1])
		} else {
			taint.Effect = v1.TaintEffect(value[0])
		}

		taints = append(taints, &taint)
	}

	if err := cloudnodeutil.AddOrUpdateTaintOnNode(c.kclient, node.Name, taints...); err != nil {
		return err
	}

	return nil
}

func taintExists(taints []v1.Taint, taintToFind *v1.Taint) bool {
	for _, taint := range taints {
		if taint.MatchTaint(taintToFind) {
			return true
		}
	}

	return false
}

func setTalosNodeLabels(c *client, meta *runtime.PlatformMetadataSpec) map[string]string {
	if meta == nil {
		return make(map[string]string)
	}

	labels := make(map[string]string, 3)

	if meta.Platform != "" {
		labels[ClusterNodePlatformLabel] = meta.Platform
	}

	if meta.Spot {
		labels[ClusterNodeLifeCycleLabel] = ClusterNodeLifeCycleLabelSpot
	}

	clusterName := c.config.Global.ClusterName
	if clusterName == "" {
		clusterName = c.talos.GetClusterName()
	}

	if clusterName != "" {
		labels[ClusterNameNodeLabel] = clusterName
	}

	return labels
}

func syncNodeLabels(c *client, node *v1.Node, nodeLabels map[string]string) error {
	nodeLabelsOrig := node.ObjectMeta.Labels
	labelsToUpdate := map[string]string{}

	for k, v := range nodeLabels {
		if r, ok := nodeLabelsOrig[k]; !ok || r != v {
			labelsToUpdate[k] = v
		}
	}

	if len(labelsToUpdate) > 0 {
		if !cloudnodeutil.AddOrUpdateLabelsOnNode(c.kclient, labelsToUpdate, node) {
			return fmt.Errorf("failed update labels for node %s", node.Name)
		}
	}

	return nil
}

// CSRNodeChecks verifies that the node hostname and IP addresses in the CSR match the ones assigned to the node.
// The CSRController has already validated the CSR parameters before calling this function.
//
// TODO: add more checks, like domain name, worker nodes don't have controlplane IPs, etc...
func CSRNodeChecks(ctx context.Context,
	kclient clientkubernetes.Interface,
	spec certificatesv1.CertificateSigningRequestSpec,
	x509cr *x509.CertificateRequest,
) (csr.Verdict, error) {
	nodeName, ok := strings.CutPrefix(spec.Username, "system:node:")
	if !ok || nodeName == "" {
		return csr.Verdict{
			Message: fmt.Sprintf("invalid CSR username: %s", spec.Username),
		}, nil
	}

	node, err := kclient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return csr.Verdict{
				Message: fmt.Sprintf("csrNodeChecks: node %s not found", nodeName),
			}, nil
		}

		return csr.Verdict{}, fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	// Status.Addresses is set by the CloudNodeController after node initialization or by the kubelet itself.
	// Once set, it contains at least the v1.NodeHostName and one v1.NodeInternalIP address
	// pkg/kubelet/nodestatus/setters.go func NodeAddress()
	//
	// Controller repeats this check approximately every 5 minutes.
	// Node lifecycle should delete the node resource if it is no longer valid.
	if len(node.Status.Addresses) == 0 {
		return csr.Verdict{}, fmt.Errorf("node not initialized yet: %s", nodeName)
	}

	var nodeAddrs []net.IP

	nodeDNSNames := []string{strings.ToLower(nodeName)}

	for _, addr := range node.Status.Addresses {
		switch addr.Type {
		case v1.NodeHostName, v1.NodeInternalDNS, v1.NodeExternalDNS:
			// Some platforms set the node hostname to its IP address.
			if addr.Type == v1.NodeHostName {
				if ip := net.ParseIP(addr.Address); ip != nil && !slices.ContainsFunc(nodeAddrs, ip.Equal) {
					nodeAddrs = append(nodeAddrs, ip)

					continue
				}
			}

			n := strings.ToLower(addr.Address)
			if !slices.Contains(nodeDNSNames, n) {
				nodeDNSNames = append(nodeDNSNames, n)
			}
		case v1.NodeInternalIP, v1.NodeExternalIP:
			ip := net.ParseIP(addr.Address)
			if ip == nil {
				continue
			}

			if slices.ContainsFunc(nodeAddrs, ip.Equal) {
				continue
			}

			nodeAddrs = append(nodeAddrs, ip)
		}
	}

	// We expect the CSR to be generated by the kubelet running on a Talos node.
	// The DNSNames in the CSR should be inside the node's NodeInternalDNS + NodeExternalDNS + NodeHostName addresses.
	// pkg/kubelet/kubelet.go:938 getLastObservedNodeAddresses() -> node.Status.Addresses
	for _, name := range x509cr.DNSNames {
		n := strings.ToLower(name)

		if slices.Contains(nodeDNSNames, n) {
			continue
		}

		return csr.Verdict{
			Message: fmt.Sprintf("csrNodeChecks: CSR DNSName %s doesn't match Node(In/Ex)ternalDNS names %q",
				name, nodeDNSNames),
		}, nil
	}

	for _, ip := range x509cr.IPAddresses {
		if !slices.ContainsFunc(nodeAddrs, ip.Equal) {
			return csr.Verdict{
				Message: fmt.Sprintf("csrNodeChecks: CSR IPAddresses %s doesn't match Node(In/Ex)ternalIP "+
					"addresses %q", ip.String(), nodeAddrs),
			}, nil
		}
	}

	return csr.Verdict{Valid: true}, nil
}
