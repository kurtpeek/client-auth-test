package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceFromTLS(t *testing.T) {
	caKey, _ := generateKey(t)
	caCert, _ := generateRootCert(t, caKey)

	deviceKeyPEM, deviceCsrPEM := generateKeyAndCSR(t)
	deviceCertPEM := signCSR(t, deviceCsrPEM, caKey, caCert)
	deviceCert, err := tls.X509KeyPair(deviceCertPEM, deviceKeyPEM)
	require.NoError(t, err)

	serverKeyPEM, serverCsrPEM := generateKeyAndCSR(t)
	serverCertPEM := signCSR(t, serverCsrPEM, caKey, caCert)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Len(t, r.TLS.PeerCertificates, 1)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	ts.StartTLS()
	defer ts.Close()

	serverPool := x509.NewCertPool()
	serverPool.AddCert(caCert)

	client := ts.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
		Certificates: []tls.Certificate{deviceCert},
		RootCAs:      serverPool,
	}

	req, err := http.NewRequest(http.MethodPut, ts.URL, nil)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Exactly(t, http.StatusOK, resp.StatusCode)
}

func generateKeyAndCSR(t *testing.T) ([]byte, []byte) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	key := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
			Organization: []string{"Awesomeness, Inc."},
			Province:     []string{"California"},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	req, err := x509.CreateCertificateRequest(rand.Reader, template, rsaKey)
	require.NoError(t, err)

	csr := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: req,
	})

	return key, csr
}

func generateRootCert(t *testing.T, key crypto.Signer) (*x509.Certificate, []byte) {
	subjectKeyIdentifier := calculateSubjectKeyIdentifier(t, key.Public())

	template := &x509.Certificate{
		SerialNumber: generateSerial(t),
		Subject: pkix.Name{
			Organization: []string{"Awesomeness, Inc."},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          subjectKeyIdentifier,
		AuthorityKeyId:        subjectKeyIdentifier,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	rootCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	return rootCert, rootCertPEM
}

// generateSerial generates a serial number using the maximum number of octets (20) allowed by RFC 5280 4.1.2.2
// (Adapted from https://github.com/cloudflare/cfssl/blob/828c23c22cbca1f7632b9ba85174aaa26e745340/signer/local/local.go#L407-L418)
func generateSerial(t *testing.T) *big.Int {
	serialNumber := make([]byte, 20)
	_, err := io.ReadFull(rand.Reader, serialNumber)
	require.NoError(t, err)

	return new(big.Int).SetBytes(serialNumber)
}

// calculateSubjectKeyIdentifier implements a common method to generate a key identifier
// from a public key, namely, by composing it from the 160-bit SHA-1 hash of the bit string
// of the public key (cf. https://tools.ietf.org/html/rfc5280#section-4.2.1.2).
// (Adapted from https://github.com/jsha/minica/blob/master/main.go).
func calculateSubjectKeyIdentifier(t *testing.T, pubKey crypto.PublicKey) []byte {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	require.NoError(t, err)

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return skid[:]
}

// signCSR signs a certificate signing request with the given CA certificate and private key
func signCSR(t *testing.T, csr []byte, caKey crypto.Signer, caCert *x509.Certificate) []byte {
	block, _ := pem.Decode(csr)
	require.NotNil(t, block, "failed to decode CSR")

	certificateRequest, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	require.NoError(t, certificateRequest.CheckSignature())

	template := x509.Certificate{
		Subject:               certificateRequest.Subject,
		PublicKeyAlgorithm:    certificateRequest.PublicKeyAlgorithm,
		PublicKey:             certificateRequest.PublicKey,
		SignatureAlgorithm:    certificateRequest.SignatureAlgorithm,
		Signature:             certificateRequest.Signature,
		SerialNumber:          generateSerial(t),
		Issuer:                caCert.Issuer,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          calculateSubjectKeyIdentifier(t, certificateRequest.PublicKey),
		BasicConstraintsValid: true,
		IPAddresses:           certificateRequest.IPAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, certificateRequest.PublicKey, caKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

// generateKey generates a 1024-bit RSA private key
func generateKey(t *testing.T) (crypto.Signer, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return key, keyPEM
}
