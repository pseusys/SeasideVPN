package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"main/generated"
	"main/utils"
	"math/big"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	GENERATE_CERT_LENGTH = 4096
	GENERATE_CERT_SERIAL = 8 * 20
	GENERATE_CERT_YEARS  = 10
)

// Metaserver structure.
// Contains gRPC server and whirlpool server, also includes connection listener.
type MetaServer struct {
	// End handler of Whirlpool server API.
	whirlpoolServer *WhirlpoolServer

	// General purpose gRPC server.
	grpcServer *grpc.Server

	// gRPC connection listener.
	listener net.Listener
}

func createTLSCredentials() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, GENERATE_CERT_LENGTH)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating private key: %v", err)
	}

	max := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(GENERATE_CERT_SERIAL), nil)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generating serial number: %v", err)
	}

	internalIP := net.ParseIP(utils.GetEnv("SEASIDE_ADDRESS"))
	externalIP := net.ParseIP(utils.GetEnv("SEASIDE_EXTERNAL"))
	properties := pkix.Name{
		Country:            []string{"SW"},
		Province:           []string{"Seaside Caerulean"},
		Locality:           []string{"Whirlpool"},
		Organization:       []string{"SeasideVPN"},
		OrganizationalUnit: []string{"caerulean-whirlpool"},
		CommonName:         "Whirlpool",
	}

	cert := &x509.Certificate{
		Subject:      properties,
		Issuer:       properties,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(GENERATE_CERT_YEARS, 0, 0),
		SerialNumber: serial,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), internalIP, externalIP, net.IPv6loopback},
	}

	serialized, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error serializing certificate: %v", err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: serialized})
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certificate, nil := tls.X509KeyPair(caPEM.Bytes(), caPrivKeyPEM.Bytes())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error creating TLS certificate: %v", err)
	}

	return certificate, nil
}

// Load TLS credentials from files.
// Certificates are expected to be in `certificates/cert.crt` and `certificates/cert.key` files.
// Certificates should be valid and contain `subjectAltName` for the current SEASIDE_ADDRESS.
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair("certificates/cert.crt", "certificates/cert.key")
	if err != nil {
		logrus.Errorf("Error reading certificates, creating new ones: %v", err)
		serverCert, err = createTLSCredentials()
		if err != nil {
			return nil, fmt.Errorf("error creating certificates: %v", err)
		}
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	// Return credentials
	return credentials.NewTLS(config), nil
}

// Start the metaserver.
// Accept context that will be used as base context.
// Return pointer to metaserver object.
func start(base context.Context) *MetaServer {
	// Create whirlpool server
	whirlpoolServer := createWhirlpoolServer(base)

	// Parse internal IP and control port from environment
	intIP := utils.GetEnv("SEASIDE_ADDRESS")
	ctrlPort := utils.GetIntEnv("SEASIDE_CTRLPORT")

	// Create TCP listener for gRPC connections
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", intIP, ctrlPort))
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}

	// Load TLS credentials from files
	credentials, err := loadTLSCredentials()
	if err != nil {
		logrus.Fatalf("failed to read credentials: %v", err)
	}

	// Create and start gRPC server
	grpcServer := grpc.NewServer(grpc.Creds(credentials))
	generated.RegisterWhirlpoolViridianServer(grpcServer, whirlpoolServer)

	// Launch server in goroutine and return the metaserver object
	go runServer(grpcServer, listener)
	return &MetaServer{
		whirlpoolServer: whirlpoolServer,
		grpcServer:      grpcServer,
		listener:        listener,
	}
}

// Run metaserver.
// Accept gRPC server and TCP connection listener.
func runServer(server *grpc.Server, listener net.Listener) {
	logrus.Infof("Starting gRPC server on address: %v", listener.Addr())
	if err := server.Serve(listener); err != nil {
		logrus.Fatalf("failed to serve: %v", err)
	}
}

// Stop metaserver.
// Should be applied for MetaServer object.
// Accept metaserver object pointer.
// Destroy gRPC and Whirlpool server, also close TCP listener.
func (server *MetaServer) stop() {
	server.grpcServer.GracefulStop()
	server.whirlpoolServer.destroyWhirlpoolServer()
	server.listener.Close()
}
