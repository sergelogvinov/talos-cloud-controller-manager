// Package talos does something.
package talos

import (
	"context"
	"io"

	"github.com/siderolabs/talos-cloud-controller-manager/pkg/certificatesigningrequest"

	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"
)

const (
	// ProviderName is the name of the Talos provider.
	ProviderName = "talos"
	// ServiceAccountName is the service account name used in kube-system namespace.
	ServiceAccountName = "talos-cloud-controller-manager"

	// ClusterNameNodeLabel is the node label of cluster-name.
	ClusterNameNodeLabel = "node.cloudprovider.kubernetes.io/clustername"
	// ClusterNodePlatformLabel is the node label of platform name.
	ClusterNodePlatformLabel = "node.cloudprovider.kubernetes.io/platform"
	// ClusterNodeLifeCycleLabel is a life cycle type of compute node.
	ClusterNodeLifeCycleLabel = "node.cloudprovider.kubernetes.io/lifecycle"
)

type cloud struct {
	cfg           *cloudConfig
	client        *client
	instancesV2   cloudprovider.InstancesV2
	csrController *certificatesigningrequest.Reconciler

	ctx  context.Context //nolint:containedctx
	stop func()
}

func init() {
	cloudprovider.RegisterCloudProvider(ProviderName, func(config io.Reader) (cloudprovider.Interface, error) {
		cfg, err := readCloudConfig(config)
		if err != nil {
			klog.ErrorS(err, "failed to read config")

			return nil, err
		}

		return newCloud(&cfg)
	})
}

func newCloud(config *cloudConfig) (cloudprovider.Interface, error) {
	client, err := newClient(context.Background(), config)
	if err != nil {
		return nil, err
	}

	instancesInterface := newInstances(client)

	return &cloud{
		cfg:         config,
		client:      client,
		instancesV2: instancesInterface,
	}, nil
}

// Initialize provides the cloud with a kubernetes client builder and may spawn goroutines
// to perform housekeeping or run custom controllers specific to the cloud provider.
// Any tasks started here should be cleaned up when the stop channel closes.
func (c *cloud) Initialize(clientBuilder cloudprovider.ControllerClientBuilder, stop <-chan struct{}) {
	c.client.kclient = clientBuilder.ClientOrDie(ServiceAccountName)

	klog.InfoS("clientset initialized")

	ctx, cancel := context.WithCancel(context.Background())
	c.ctx = ctx
	c.stop = cancel

	if err := c.client.refreshTalosClient(c.ctx); err != nil {
		klog.ErrorS(err, "failed to initialized talos client")

		return
	}

	// Broadcast the upstream stop signal to all provider-level goroutines
	// watching the provider's context for cancellation.
	go func(provider *cloud) {
		<-stop
		klog.V(3).InfoS("received cloud provider termination signal")
		provider.stop()
	}(c)

	if c.cfg.Global.ApproveNodeCSR {
		klog.InfoS("Started CSR Node controller")

		c.csrController = certificatesigningrequest.NewCsrController(c.client.kclient, csrNodeChecks)
		go c.csrController.Run(c.ctx)
	}

	klog.InfoS("talos initialized")
}

// LoadBalancer returns a balancer interface.
// Also returns true if the interface is supported, false otherwise.
func (c *cloud) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return nil, false
}

// Instances returns an instances interface.
// Also returns true if the interface is supported, false otherwise.
func (c *cloud) Instances() (cloudprovider.Instances, bool) {
	return nil, false
}

// InstancesV2 is an implementation for instances and should only be implemented by external cloud providers.
// Implementing InstancesV2 is behaviorally identical to Instances but is optimized to significantly reduce
// API calls to the cloud provider when registering and syncing nodes.
// Also returns true if the interface is supported, false otherwise.
func (c *cloud) InstancesV2() (cloudprovider.InstancesV2, bool) {
	return c.instancesV2, c.instancesV2 != nil
}

// Zones returns a zones interface.
// Also returns true if the interface is supported, false otherwise.
func (c *cloud) Zones() (cloudprovider.Zones, bool) {
	return nil, false
}

// Clusters is not implemented.
func (c *cloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// Routes is not implemented.
func (c *cloud) Routes() (cloudprovider.Routes, bool) {
	return nil, false
}

// ProviderName returns the cloud provider ID.
func (c *cloud) ProviderName() string {
	return ProviderName
}

// HasClusterID is not implemented.
func (c *cloud) HasClusterID() bool {
	return true
}
