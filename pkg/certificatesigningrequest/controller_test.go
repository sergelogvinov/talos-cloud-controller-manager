package certificatesigningrequest_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	csr "github.com/siderolabs/talos-cloud-controller-manager/pkg/certificatesigningrequest"

	certificatesv1 "k8s.io/api/certificates/v1"
	clientkubernetes "k8s.io/client-go/kubernetes"
)

const (
	hostname     = "talos-1"
	organization = "system:nodes"
	username     = "system:node:" + hostname
)

var rsaKey *rsa.PrivateKey

func init() {
	res, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	rsaKey = res
}

func generateCSR(t *testing.T, csrTemplate *x509.CertificateRequest) []byte {
	t.Helper()

	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, rsaKey)
	if err != nil {
		t.Fatalf("Can not create Certificate Request %v", err)
	}

	csr := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrCertificate,
	})

	return csr
}

func TestNewCsrController(t *testing.T) {
	t.Parallel()

	kclient := &clientkubernetes.Clientset{}

	controller := csr.NewCsrController(kclient,
		func(context.Context, clientkubernetes.Interface, certificatesv1.CertificateSigningRequestSpec, *x509.CertificateRequest) (csr.Verdict, error) {
			return csr.Verdict{Valid: true}, nil
		})

	assert.NotNil(t, controller)
}

func TestControllerReconcileCSR(t *testing.T) {
	t.Parallel()

	controller := csr.NewCsrController(&clientkubernetes.Clientset{},
		func(_ context.Context, _ clientkubernetes.Interface, _ certificatesv1.CertificateSigningRequestSpec, x509cr *x509.CertificateRequest) (csr.Verdict, error) {
			if reflect.DeepEqual(x509cr.DNSNames, []string{"error"}) {
				return csr.Verdict{Message: "someting went wrong"}, fmt.Errorf("someting went wrong")
			}

			if !reflect.DeepEqual(x509cr.DNSNames, []string{hostname}) {
				return csr.Verdict{Message: "DNS names do not match expected hostname"}, nil
			}

			return csr.Verdict{Valid: true}, nil
		})

	assert.NotNil(t, controller)

	tests := []struct {
		msg             string
		csr             certificatesv1.CertificateSigningRequest
		expectedUpdate  bool
		expectedError   error
		expectedMessage string
	}{
		{
			msg: "Not Kubelet CSR",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: "random name",
				},
			},
			expectedUpdate: false,
		},
		{
			msg: "approved or denied CSR",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: certificatesv1.KubeletServingSignerName,
				},
				Status: certificatesv1.CertificateSigningRequestStatus{
					Conditions: []certificatesv1.CertificateSigningRequestCondition{
						{},
					},
				},
			},
			expectedUpdate: false,
		},
		{
			msg: "Already signed CSR",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: certificatesv1.KubeletServingSignerName,
				},
				Status: certificatesv1.CertificateSigningRequestStatus{
					Certificate: []byte("somecert"),
				},
			},
			expectedUpdate: false,
		},
		{
			msg: "Wrong CSR body",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: certificatesv1.KubeletServingSignerName,
					Username:   username,
					Request:    []byte("somecert"),
				},
			},
			expectedUpdate:  true,
			expectedMessage: "This CSR was denied by Talos Cloud Controller Manager, reason: PEM block type must be CERTIFICATE REQUEST",
		},
		{
			msg: "Approved CSR",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: certificatesv1.KubeletServingSignerName,
					Username:   username,
					Request: generateCSR(t, &x509.CertificateRequest{
						Subject: pkix.Name{
							Organization: []string{organization},
							CommonName:   username,
						},
						DNSNames:           []string{hostname},
						SignatureAlgorithm: x509.SHA256WithRSA,
					}),
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageDigitalSignature,
						certificatesv1.UsageServerAuth,
					},
				},
			},
			expectedUpdate:  true,
			expectedMessage: "This CSR was approved by Talos Cloud Controller Manager",
		},
		{
			msg: "Wrong CSR DNS-IP",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: certificatesv1.KubeletServingSignerName,
					Username:   username,
					Request: generateCSR(t, &x509.CertificateRequest{
						Subject: pkix.Name{
							Organization: []string{organization},
							CommonName:   username,
						},
						SignatureAlgorithm: x509.SHA256WithRSA,
					}),
				},
			},
			expectedUpdate:  true,
			expectedMessage: "This CSR was denied by Talos Cloud Controller Manager, reason: DNS or IP subjectAltName is required",
		},
		{
			msg: "Denied CSR with invalid DNS",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: certificatesv1.KubeletServingSignerName,
					Username:   username,
					Request: generateCSR(t, &x509.CertificateRequest{
						Subject: pkix.Name{
							Organization: []string{organization},
							CommonName:   username,
						},
						DNSNames:           []string{"invalid"},
						IPAddresses:        []net.IP{net.ParseIP("1.2.3.4")},
						SignatureAlgorithm: x509.SHA256WithRSA,
					}),
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageDigitalSignature,
						certificatesv1.UsageServerAuth,
					},
				},
			},
			expectedUpdate:  true,
			expectedMessage: "This CSR was denied by Talos Cloud Controller Manager, reason: DNS names do not match expected hostname",
		},
		{
			msg: "ProviderChecks has an error",
			csr: certificatesv1.CertificateSigningRequest{
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: certificatesv1.KubeletServingSignerName,
					Username:   username,
					Request: generateCSR(t, &x509.CertificateRequest{
						Subject: pkix.Name{
							Organization: []string{organization},
							CommonName:   username,
						},
						DNSNames:           []string{"error"},
						IPAddresses:        []net.IP{net.ParseIP("1.2.3.4")},
						SignatureAlgorithm: x509.SHA256WithRSA,
					}),
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageDigitalSignature,
						certificatesv1.UsageServerAuth,
					},
				},
			},
			expectedUpdate: false,
			expectedError:  fmt.Errorf("providerChecks has an error: someting went wrong"),
		},
	}

	for _, testCase := range tests {
		t.Run(fmt.Sprint(testCase.msg), func(t *testing.T) {
			t.Parallel()

			update, err := controller.Reconcile(t.Context(), &testCase.csr)

			if testCase.expectedError != nil {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), testCase.expectedError.Error())
				assert.Equal(t, testCase.expectedUpdate, update)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, testCase.expectedUpdate, update)

				if testCase.expectedUpdate {
					assert.Len(t, testCase.csr.Status.Conditions, 1)
					assert.Equal(t, testCase.expectedMessage, testCase.csr.Status.Conditions[0].Message)
				}
			}
		})
	}
}
