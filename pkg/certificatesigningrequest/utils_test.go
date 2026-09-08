//nolint:testpackage // Need to reach functions.
package certificatesigningrequest

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	certificatesv1 "k8s.io/api/certificates/v1"
)

func TestParseCSRValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg           string
		pemCSR        []byte
		csr           certificatesv1.CertificateSigningRequest
		expectedError error
	}{
		{
			msg:           "empty PEM CSR",
			pemCSR:        []byte(""),
			expectedError: errNotCertificateRequest,
		},
		{
			msg:           "empty PEM data",
			pemCSR:        []byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"),
			expectedError: asn1.SyntaxError{Msg: "sequence truncated"},
		},
		{
			msg:           "wrong PEM data",
			pemCSR:        []byte("-----BEGIN CERTIFICATE REQUEST-----\n1234567890\n-----END CERTIFICATE REQUEST-----\n"),
			expectedError: errNotCertificateRequest,
		},
	}

	for _, testCase := range tests {
		t.Run(fmt.Sprint(testCase.msg), func(t *testing.T) {
			t.Parallel()

			csr, err := parseCSR(testCase.pemCSR)
			assert.NotNil(t, err)
			assert.Nil(t, csr)
			assert.Contains(t, err.Error(), testCase.expectedError.Error())
		})
	}
}

func TestValidateKubeletServingCSRValid(t *testing.T) {
	t.Parallel()

	org := "system:nodes"
	cname := "system:node:valid"
	usages := []certificatesv1.KeyUsage{
		certificatesv1.UsageKeyEncipherment,
		certificatesv1.UsageDigitalSignature,
		certificatesv1.UsageServerAuth,
	}

	tests := []struct {
		msg     string
		x509cr  x509.CertificateRequest
		csrSpec certificatesv1.CertificateSigningRequestSpec
	}{
		{
			msg: "Only DNSNames",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames: []string{"valid", "valid.example.com"},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
		},
		{
			msg: "Only IPAddresses",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				IPAddresses: []net.IP{net.ParseIP("1.2.3.4")},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
		},
		{
			msg: "Key usages RSA",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames:    []string{"valid"},
				IPAddresses: []net.IP{net.ParseIP("1.2.3.4")},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages: []certificatesv1.KeyUsage{
					certificatesv1.UsageKeyEncipherment,
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageServerAuth,
				},
			},
		},
		{
			msg: "Key usages ECDSA",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames:    []string{"valid"},
				IPAddresses: []net.IP{net.ParseIP("1.2.3.4")},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageServerAuth,
				},
			},
		},
	}

	for _, testCase := range tests {
		t.Run(fmt.Sprint(testCase.msg), func(t *testing.T) {
			t.Parallel()

			err := validateKubeletServingCSR(&testCase.x509cr, testCase.csrSpec)
			assert.NoError(t, err)
		})
	}
}

func TestValidateKubeletServingCSRInvalid(t *testing.T) {
	t.Parallel()

	org := "system:nodes"
	cname := "system:node:invalid"
	dnsNames := []string{"valid"}
	ipAddresses := []net.IP{net.ParseIP("1.2.3.4")}

	usages := []certificatesv1.KeyUsage{
		certificatesv1.UsageDigitalSignature,
		certificatesv1.UsageServerAuth,
	}

	tests := []struct {
		msg           string
		x509cr        x509.CertificateRequest
		csrSpec       certificatesv1.CertificateSigningRequestSpec
		expectedError error
	}{
		{
			msg: "DNSNames or IPAddresses required",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errDNSOrIPSANRequired,
		},
		{
			msg: "Invalid DNSNames",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames: []string{"kubernetes"},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errDNSNameNotAllowed,
		},
		{
			msg: "Invalid DNSNames long form",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames: []string{"kubernetes.default.svc"},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errDNSNameNotAllowed,
		},
		{
			msg: "Invalid DNSNames wildcard",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames: []string{"*.example.com"},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errDNSNameNotAllowed,
		},
		{
			msg: "Invalid Organization",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{"invalid"},
				},
				DNSNames:    dnsNames,
				IPAddresses: ipAddresses,
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errOrganizationNotSystemNodes,
		},
		{
			msg: "Invalid CommonName",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   "invalid",
					Organization: []string{org},
				},
				DNSNames:    dnsNames,
				IPAddresses: ipAddresses,
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errCommonNameNotSystemNode,
		},
		{
			msg: "Invalid CommonName empty node name",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   "system:node:",
					Organization: []string{org},
				},
				DNSNames: []string{"invalid"},
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errCommonNameNotSystemNode,
		},
		{
			msg: "CommonName does not match username",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   "system:node:other",
					Organization: []string{org},
				},
				DNSNames:    dnsNames,
				IPAddresses: ipAddresses,
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errCommonNameNotMatchingUsername,
		},
		{
			msg: "Has email addresses",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				EmailAddresses: []string{"invalid"},
				DNSNames:       dnsNames,
				IPAddresses:    ipAddresses,
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errEmailSANNotAllowed,
		},
		{
			msg: "Has URI addresses",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				URIs:        []*url.URL{{Scheme: "https", Host: "invalid"}},
				DNSNames:    dnsNames,
				IPAddresses: ipAddresses,
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages:   usages,
			},
			expectedError: errURISANNotAllowed,
		},
		{
			msg: "Invalid key usages",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames:    dnsNames,
				IPAddresses: ipAddresses,
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageServerAuth,
					certificatesv1.UsageClientAuth,
				},
			},
			expectedError: errKeyUsageMismatch,
		},
		{
			msg: "Invalid key usages, ServerAuth missing",
			x509cr: x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   cname,
					Organization: []string{org},
				},
				DNSNames:    dnsNames,
				IPAddresses: ipAddresses,
			},
			csrSpec: certificatesv1.CertificateSigningRequestSpec{
				Username: cname,
				Usages: []certificatesv1.KeyUsage{
					certificatesv1.UsageDigitalSignature,
					certificatesv1.UsageDigitalSignature,
				},
			},
			expectedError: errKeyUsageMismatch,
		},
	}

	for _, testCase := range tests {
		t.Run(fmt.Sprint(testCase.msg), func(t *testing.T) {
			t.Parallel()

			err := validateKubeletServingCSR(&testCase.x509cr, testCase.csrSpec)
			assert.NotNil(t, err)
			assert.Contains(t, err.Error(), testCase.expectedError.Error())
		})
	}
}
