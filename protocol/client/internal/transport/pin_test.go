package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, commonName string, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{commonName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}
	return cert, priv
}

func TestPinManagement(t *testing.T) {
	ClearPins()
	if HasPins() {
		t.Fatalf("expected no pins initially")
	}

	cert1, _ := generateTestCert(t, "node1.example.com", false)
	cert2, _ := generateTestCert(t, "node2.example.com", false)

	pin1 := CertSPKI(cert1)
	pin2 := CertSPKI(cert2)

	AddPins(pin1)
	if !HasPins() {
		t.Fatalf("expected HasPins() to be true")
	}
	if !MatchSPKI(cert1) {
		t.Fatalf("expected cert1 to match pin1")
	}
	if MatchSPKI(cert2) {
		t.Fatalf("cert2 should not match before being added")
	}

	AddPins(pin2)
	if !MatchSPKI(cert2) {
		t.Fatalf("cert2 should match after being added")
	}
	if !MatchSPKI(cert1) {
		t.Fatalf("cert1 should still match")
	}

	ClearPins()
	if HasPins() {
		t.Fatalf("pins should be empty after ClearPins")
	}
}

func TestDualTrackVerification(t *testing.T) {
	ClearPins()

	caCert, caPriv := generateTestCert(t, "My Test Root CA", true)

	leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject: pkix.Name{
			CommonName: "edge.example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"edge.example.com"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Set custom root pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)
	SetGlobal(rootPool)

	// Case 1: SPKI Pin matches
	pin := CertSPKI(leafCert)
	SetPins([]string{pin})
	verifyFn := MakeVerifyPeerCertificate("edge.example.com")
	if err := verifyFn([][]byte{leafDER, caCert.Raw}, nil); err != nil {
		t.Fatalf("expected verify to pass with matching pin, got: %v", err)
	}

	// Case 2: SPKI Pin does NOT match, but trusted CA matches
	SetPins([]string{"different-spki-pin-hash"})
	if err := verifyFn([][]byte{leafDER, caCert.Raw}, nil); err != nil {
		t.Fatalf("expected verify to pass via trusted CA fallback, got: %v", err)
	}

	// Case 3: Untrusted cert, no pin match -> MUST FAIL
	untrustedCert, _ := generateTestCert(t, "evil.example.com", false)
	if err := verifyFn([][]byte{untrustedCert.Raw}, nil); err == nil {
		t.Fatalf("expected verify to FAIL for untrusted certificate")
	}
}
