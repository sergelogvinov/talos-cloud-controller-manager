// Package certificatesigningrequest implements the controller for Node Certificate Signing Request.
package certificatesigningrequest

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/siderolabs/talos-cloud-controller-manager/pkg/metrics"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	clientkubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// Verdict represents the result of validating a CertificateSigningRequest.
type Verdict struct {
	Valid   bool
	Message string
}

// ProviderChecks is a function that checks if the CertificateSigningRequest is valid in the provider.
type ProviderChecks func(context.Context, clientkubernetes.Interface, certificatesv1.CertificateSigningRequestSpec, *x509.CertificateRequest) (Verdict, error)

// Reconciler is the controller for CertificateSigningRequest.
type Reconciler struct {
	kclient        clientkubernetes.Interface
	providerChecks ProviderChecks
}

// NewCsrController returns a new CertificateSigningRequest controller.
func NewCsrController(kclient clientkubernetes.Interface, fn ProviderChecks) *Reconciler {
	return &Reconciler{
		kclient:        kclient,
		providerChecks: fn,
	}
}

// Run the CertificateSigningRequest controller.
func (r *Reconciler) Run(ctx context.Context) {
	watchTimeoutSeconds := int64(60 * 5) // 5 minutes

	for {
		watcher, err := r.kclient.
			CertificatesV1().
			CertificateSigningRequests().
			Watch(ctx, metav1.ListOptions{
				Watch:          true,
				TimeoutSeconds: &watchTimeoutSeconds,
			})
		if err != nil {
			klog.ErrorS(err, "CertificateSigningRequestReconciler: failed to list CSR resources")
			time.Sleep(10 * time.Second) // Pause for a while before retrying, otherwise we'll spam error logs.

			continue
		}

		csrWatcher := k8swatch.Filter(watcher, func(in k8swatch.Event) (out k8swatch.Event, keep bool) {
			if in.Type != k8swatch.Added {
				return in, false
			}

			return in, true
		})

	watch:
		for {
			select {
			case <-ctx.Done():
				klog.V(4).InfoS("CertificateSigningRequestReconciler: context canceled, terminating")

				return

			case event, ok := <-csrWatcher.ResultChan():
				if !ok {
					// Server timeout closed the watcher channel, loop again to re-create a new one.
					klog.V(5).InfoS("CertificateSigningRequestReconciler: API server closed watcher channel")

					break watch
				}

				csr, ok := event.Object.DeepCopyObject().(*certificatesv1.CertificateSigningRequest)
				if !ok {
					klog.V(5).InfoS("CertificateSigningRequestReconciler: expected event of type *CertificateSigningRequest",
						"kind", event.Object.GetObjectKind())

					continue
				}

				update, err := r.Reconcile(ctx, csr)
				if err != nil {
					klog.ErrorS(err, "CertificateSigningRequestReconciler: failed to reconcile CSR", "name", csr.Name)

					continue
				}

				if update {
					if _, err := r.kclient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{}); err != nil {
						klog.ErrorS(err, "CertificateSigningRequestReconciler: failed to approve/deny CSR", "name", csr.Name)
					}
				}
			}
		}
	}
}

// Reconcile the CertificateSigningRequest.
func (r *Reconciler) Reconcile(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (bool, error) {
	switch {
	case csr.Spec.SignerName != certificatesv1.KubeletServingSignerName:
		klog.V(5).InfoS("CertificateSigningRequestReconciler: ignoring, not a Kubelet serving certificate",
			"signer", csr.Spec.SignerName)

		return false, nil

	case len(csr.Status.Certificate) != 0:
		klog.V(5).InfoS("CertificateSigningRequestReconciler: ignoring, already signed",
			"username", csr.Spec.Username)

		return false, nil

	case len(csr.Status.Conditions) > 0:
		klog.V(5).InfoS("CertificateSigningRequestReconciler: ignoring, already approved or denied",
			"signer", csr.Spec.SignerName)

		return false, nil
	}

	x509cr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		klog.ErrorS(err, "CertificateSigningRequestReconciler: failed to parse CSR", "name", csr.Name)
		r.updateApproval(csr, false, err.Error())

		return true, nil
	}

	err = validateKubeletServingCSR(x509cr, csr.Spec)
	if err != nil {
		klog.ErrorS(err, "CertificateSigningRequestReconciler: failed to validate CSR", "name", csr.Name)
		r.updateApproval(csr, false, err.Error())

		return true, nil
	}

	verdict, err := r.providerChecks(ctx, r.kclient, csr.Spec, x509cr)
	if err != nil {
		return false, fmt.Errorf("providerChecks has an error: %v", err)
	}

	r.updateApproval(csr, verdict.Valid, verdict.Message)

	if !verdict.Valid {
		klog.InfoS("CertificateSigningRequestReconciler: has been denied", "name", csr.Name)
	} else {
		klog.InfoS("CertificateSigningRequestReconciler: has been approved", "name", csr.Name)
	}

	return true, nil
}

func (r *Reconciler) updateApproval(csr *certificatesv1.CertificateSigningRequest, approved bool, reason string) {
	reasonMessage := ""
	if reason != "" {
		reasonMessage = fmt.Sprintf(", reason: %s", reason)
	}

	if approved {
		metrics.CSRApprovedCount(metrics.ApprovalStatusApprove)

		csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:           certificatesv1.CertificateApproved,
			Status:         corev1.ConditionTrue,
			Reason:         "Approved by TalosCloudControllerManager",
			Message:        "This CSR was approved by Talos Cloud Controller Manager" + reasonMessage,
			LastUpdateTime: metav1.Time{Time: time.Now().UTC()},
		})
	} else {
		metrics.CSRApprovedCount(metrics.ApprovalStatusDeny)

		csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:           certificatesv1.CertificateDenied,
			Status:         corev1.ConditionTrue,
			Reason:         "Denied by TalosCloudControllerManager",
			Message:        "This CSR was denied by Talos Cloud Controller Manager" + reasonMessage,
			LastUpdateTime: metav1.Time{Time: time.Now().UTC()},
		})
	}
}
