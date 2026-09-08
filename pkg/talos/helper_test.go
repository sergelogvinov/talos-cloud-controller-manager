package talos

import (
	"crypto/x509"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/siderolabs/talos-cloud-controller-manager/pkg/certificatesigningrequest"
	"github.com/siderolabs/talos-cloud-controller-manager/pkg/nodeselector"
	"github.com/siderolabs/talos-cloud-controller-manager/pkg/transformer"
	"github.com/siderolabs/talos/pkg/machinery/nethelpers"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"

	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetNodeAddresses(t *testing.T) {
	cfg := cloudConfig{}

	for _, tt := range []struct {
		name       string
		cfg        cloudConfig
		platform   string
		features   *transformer.NodeFeaturesFlagSpec
		providedIP string
		ifaces     []network.AddressStatusSpec
		expected   []v1.NodeAddress
	}{
		{
			name:       "nocloud has no PublicIPs",
			cfg:        cfg,
			platform:   "nocloud",
			providedIP: "192.168.0.1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("fd15:1:2::192:168:0:1/64")},
				{Address: netip.MustParsePrefix("fd43:fe8a:be2:ab02:dc3c:38ff:fe51:5022/64"), LinkName: "kubespan"},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
			},
		},
		{
			name:       "nocloud has dualstack",
			cfg:        cfg,
			platform:   "nocloud",
			providedIP: "192.168.0.1,fd00:192:168:0::1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("fd00:192:168:0::1/64")},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
				{Type: v1.NodeInternalIP, Address: "fd00:192:168::1"},
			},
		},
		{
			name:       "nocloud has many PublicIPs",
			cfg:        cfg,
			platform:   "nocloud",
			providedIP: "192.168.0.1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("fd15:1:2::192:168:0:1/64")},
				{Address: netip.MustParsePrefix("1.2.3.4/24")},
				{Address: netip.MustParsePrefix("4.3.2.1/24")},
				{Address: netip.MustParsePrefix("2001:1234::1/64")},
				{Address: netip.MustParsePrefix("2001:1234:4321::32/64")},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeExternalIP, Address: "2001:1234::1"},
			},
		},
		{
			name:       "nocloud has many PublicIPs (IPv6 preferred)",
			cfg:        cloudConfig{Global: cloudConfigGlobal{PreferIPv6: true}},
			platform:   "nocloud",
			providedIP: "192.168.0.1,fd15:1:2::192:168:0:1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("fd15:1:2::192:168:0:1/64")},
				{Address: netip.MustParsePrefix("1.2.3.4/24")},
				{Address: netip.MustParsePrefix("4.3.2.1/24")},
				{Address: netip.MustParsePrefix("2001:1234::1/64")},
				{Address: netip.MustParsePrefix("2001:1234:4321::32/64")},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "fd15:1:2:0:192:168:0:1"},
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
				{Type: v1.NodeExternalIP, Address: "2001:1234::1"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
			},
		},
		{
			name:       "metal has PublicIPs",
			cfg:        cfg,
			platform:   "metal",
			providedIP: "192.168.0.1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("fd15:1:2::192:168:0:1/64")},
				{Address: netip.MustParsePrefix("1.2.3.4/24")},
				{Address: netip.MustParsePrefix("2001:1234:1:2:3:4:5:6/64"), Flags: nethelpers.AddressFlags(nethelpers.AddressManagementTemp)},
				{Address: netip.MustParsePrefix("2001:1234::1/64"), Flags: nethelpers.AddressFlags(nethelpers.AddressPermanent)},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeExternalIP, Address: "2001:1234::1"},
			},
		},
		{
			name:       "gcp has provided PublicIPs",
			cfg:        cfg,
			platform:   "gcp",
			providedIP: "192.168.0.1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("1.2.3.4/24"), LinkName: "external"},
				{Address: netip.MustParsePrefix("4.3.2.1/24")},
				{Address: netip.MustParsePrefix("2001:1234::1/128"), LinkName: "external"},
				{Address: netip.MustParsePrefix("2001:1234::123/64")},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeExternalIP, Address: "2001:1234::1"},
			},
		},
		{
			name:       "gcp dualstack with public IPs",
			cfg:        cfg,
			platform:   "gcp",
			providedIP: "192.168.0.1,fd15:1:2::192:168:0:1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("1.2.3.4/24"), LinkName: "external"},
				{Address: netip.MustParsePrefix("2001:1234::123/64")},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
				{Type: v1.NodeInternalIP, Address: "fd15:1:2:0:192:168:0:1"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
			},
		},
		{
			name:       "gcp dualstack with public IPs and featureflag",
			cfg:        cfg,
			platform:   "gcp",
			features:   &transformer.NodeFeaturesFlagSpec{PublicIPDiscovery: true},
			providedIP: "192.168.0.1,fd15:1:2::192:168:0:1",
			ifaces: []network.AddressStatusSpec{
				{Address: netip.MustParsePrefix("192.168.0.1/24")},
				{Address: netip.MustParsePrefix("fe80::e0b5:71ff:fe24:7e60/64")},
				{Address: netip.MustParsePrefix("1.2.3.4/24"), LinkName: "external"},
				{Address: netip.MustParsePrefix("2001:1234::123/64")},
			},
			expected: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: "192.168.0.1"},
				{Type: v1.NodeInternalIP, Address: "fd15:1:2:0:192:168:0:1"},
				{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
				{Type: v1.NodeExternalIP, Address: "2001:1234::123"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			addresses := getNodeAddresses(&tt.cfg, tt.platform, tt.features, strings.Split(tt.providedIP, ","), tt.ifaces)

			assert.Equal(t, tt.expected, addresses)
		})
	}
}

func TestSyncNodeLabels(t *testing.T) {
	t.Setenv("TALOSCONFIG", "../../hack/talosconfig")

	cfg := cloudConfig{
		Global: cloudConfigGlobal{
			ClusterName: "test-cluster",
		},
		Transformations: []transformer.NodeTerm{
			{
				NodeSelector: []nodeselector.NodeSelectorTerm{
					{
						MatchExpressions: []nodeselector.NodeSelectorRequirement{
							{
								Key:      "Hostname",
								Operator: "Regexp",
								Values:   []string{"^web-.+$"},
							},
						},
					},
				},
				Labels: map[string]string{
					"node-role.kubernetes.io/web": "",
				},
			},
		},
	}
	ctx := t.Context()
	nodes := &v1.NodeList{
		Items: []v1.Node{
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "web-1",
				},
			},
		},
	}

	client, err := newClient(ctx, &cfg)
	assert.NoError(t, err)

	client.kclient = fake.NewClientset(nodes)

	for _, tt := range []struct {
		name          string
		node          *v1.Node
		meta          *runtime.PlatformMetadataSpec
		expectedError error
		expectedNode  *v1.Node
	}{
		{
			name: "node has no metadata",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
			},
			meta:          &runtime.PlatformMetadataSpec{},
			expectedError: nil,
			expectedNode: &v1.Node{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
					Labels: map[string]string{
						ClusterNameNodeLabel: "test-cluster",
					},
				},
			},
		},
		{
			name: "node with platform name",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
			},
			meta: &runtime.PlatformMetadataSpec{
				Platform: "metal",
				Hostname: "node1",
			},
			expectedError: nil,
			expectedNode: &v1.Node{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
					Labels: map[string]string{
						ClusterNameNodeLabel:     "test-cluster",
						ClusterNodePlatformLabel: "metal",
					},
				},
			},
		},
		{
			name: "spot node",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
			},
			meta: &runtime.PlatformMetadataSpec{
				Platform: "metal",
				Hostname: "node1",
				Spot:     true,
			},
			expectedError: nil,
			expectedNode: &v1.Node{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
					Labels: map[string]string{
						ClusterNameNodeLabel:      "test-cluster",
						ClusterNodePlatformLabel:  "metal",
						ClusterNodeLifeCycleLabel: ClusterNodeLifeCycleLabelSpot,
					},
				},
			},
		},
		{
			name: "node with custom labels",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "web-1",
				},
			},
			meta: &runtime.PlatformMetadataSpec{
				Platform: "nocloud",
				Hostname: "web-1",
			},
			expectedError: nil,
			expectedNode: &v1.Node{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "web-1",
					Labels: map[string]string{
						ClusterNameNodeLabel:          "test-cluster",
						ClusterNodePlatformLabel:      "nocloud",
						"node-role.kubernetes.io/web": "",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nodeSpec, err := transformer.TransformNode(client.config.Transformations, tt.meta, nil)
			assert.NoError(t, err)

			labels := setTalosNodeLabels(client, tt.meta)

			if nodeSpec != nil && nodeSpec.Labels != nil {
				maps.Copy(labels, nodeSpec.Labels)
			}

			err = syncNodeLabels(client, tt.node, labels)

			assert.Equal(t, tt.expectedError, err)

			node, err := client.kclient.CoreV1().Nodes().Get(ctx, tt.node.Name, metav1.GetOptions{})
			assert.NoError(t, err)

			node.ManagedFields = nil // ignore managed fields in comparison
			assert.Equal(t, tt.expectedNode, node)
		})
	}
}

func TestCSRNodeChecks(t *testing.T) {
	ctx := t.Context()
	nodes := &v1.NodeList{
		Items: []v1.Node{
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node2",
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-int",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "1.2.3.4",
						},
					},
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-int-ext",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "1.2.3.4",
						},
						{
							Type:    v1.NodeExternalIP,
							Address: "2000::1",
						},
					},
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-hostname",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "1.2.3.4",
						},
						{
							Type:    v1.NodeHostName,
							Address: "node-hostname",
						},
						{
							Type:    v1.NodeInternalDNS,
							Address: "node-hostname.internal",
						},
					},
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "ip-192-168-135-66",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "192.168.135.66",
						},
						{
							Type:    v1.NodeHostName,
							Address: "ip-192-168-135-66.eu-central-1.compute.internal",
						},
						{
							Type:    v1.NodeInternalDNS,
							Address: "ip-192-168-135-66.eu-central-1.compute.internal",
						},
					},
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-dns",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "10.0.0.5",
						},
						{
							Type:    v1.NodeHostName,
							Address: "node-dns",
						},
						{
							Type:    v1.NodeInternalDNS,
							Address: "node-dns.internal.example.com",
						},
						{
							Type:    v1.NodeExternalDNS,
							Address: "node-dns-public.example.com",
						},
					},
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "192.168.113.10",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeHostName,
							Address: "192.168.113.10",
						},
					},
				},
			},
			{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Node",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-ipv6-noncanonical",
				},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{
							Type:    v1.NodeInternalIP,
							Address: "2001:0DB8:0000:0000:0000:0000:0000:0001",
						},
						{
							Type:    v1.NodeHostName,
							Address: "node-ipv6-noncanonical",
						},
					},
				},
			},
		},
	}

	for _, tt := range []struct {
		name          string
		spec          certificatesv1.CertificateSigningRequestSpec
		cert          *x509.CertificateRequest
		expectedError error
		expected      certificatesigningrequest.Verdict
	}{
		{
			name: "fake node",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-non-existing",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-non-existing"},
			},
			expectedError: nil,
			expected: certificatesigningrequest.Verdict{
				Message: "csrNodeChecks: node node-non-existing not found",
			},
		},
		{
			name: "empty node1",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node1",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node1"},
			},
			expectedError: fmt.Errorf("node not initialized yet: node1"),
			expected:      certificatesigningrequest.Verdict{},
		},
		{
			name: "empty node2",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node2",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node2"},
			},
			expectedError: fmt.Errorf("node not initialized yet: node2"),
			expected:      certificatesigningrequest.Verdict{},
		},
		{
			name: "node with IP",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-int",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-int"},
				IPAddresses: []net.IP{
					net.ParseIP("1.2.3.4"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with fake IPs",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-hostname",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-hostname", "node-hostname.internal"},
				IPAddresses: []net.IP{
					net.ParseIP("1.2.3.4"),
					net.ParseIP("2000::1"),
				},
			},
			expectedError: nil,
			expected: certificatesigningrequest.Verdict{
				Message: `csrNodeChecks: CSR IPAddresses 2000::1 doesn't match Node(In/Ex)ternalIP addresses ["1.2.3.4"]`,
			},
		},
		{
			name: "node with node-IP",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-int",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-int"},
				IPAddresses: []net.IP{
					net.ParseIP("1.2.3.4"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with node-IPs",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-int-ext",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-int-ext"},
				IPAddresses: []net.IP{
					net.ParseIP("1.2.3.4"),
					net.ParseIP("2000::1"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with matching hostname",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-hostname",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-hostname.internal"},
				IPAddresses: []net.IP{
					net.ParseIP("1.2.3.4"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with mismatched hostname",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-hostname",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"some-other-name"},
				IPAddresses: []net.IP{
					net.ParseIP("1.2.3.4"),
				},
			},
			expectedError: nil,
			expected: certificatesigningrequest.Verdict{
				Message: `csrNodeChecks: CSR DNSName some-other-name doesn't match Node(In/Ex)ternalDNS names ["node-hostname" "node-hostname.internal"]`,
			},
		},
		{
			name: "node with case-insensitive hostname",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-hostname",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"NODE-HOSTNAME.INTERNAL"},
				IPAddresses: []net.IP{
					net.ParseIP("1.2.3.4"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with hostname as FQDN prefix",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:ip-192-168-135-66",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"ip-192-168-135-66.eu-central-1.compute.internal"},
				IPAddresses: []net.IP{
					net.ParseIP("192.168.135.66"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with internal and external DNS names",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-dns",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-dns", "node-dns.internal.example.com", "NODE-DNS-PUBLIC.example.com"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.5"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with one valid and one foreign DNS name",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-dns",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-dns", "other-node.internal.example.com"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.5"),
				},
			},
			expectedError: nil,
			expected: certificatesigningrequest.Verdict{
				Message: `csrNodeChecks: CSR DNSName other-node.internal.example.com doesn't match Node(In/Ex)ternalDNS names ` +
					`["node-dns" "node-dns.internal.example.com" "node-dns-public.example.com"]`,
			},
		},
		{
			name: "node with hostname set to its IP address",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:192.168.113.10",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"192.168.113.10"},
				IPAddresses: []net.IP{
					net.ParseIP("192.168.113.10"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
		{
			name: "node with non-canonical IPv6 address matches canonical CSR IP",
			spec: certificatesv1.CertificateSigningRequestSpec{
				Username: "system:node:node-ipv6-noncanonical",
			},
			cert: &x509.CertificateRequest{
				DNSNames: []string{"node-ipv6-noncanonical"},
				IPAddresses: []net.IP{
					net.ParseIP("2001:db8::1"),
				},
			},
			expectedError: nil,
			expected:      certificatesigningrequest.Verdict{Valid: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			kclient := fake.NewClientset(nodes)
			approve, err := CSRNodeChecks(ctx, kclient, tt.spec, tt.cert)

			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expected, approve)
		})
	}
}
