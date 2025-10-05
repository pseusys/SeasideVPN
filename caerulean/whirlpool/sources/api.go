package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"main/crypto"
	"main/generated"
	"main/utils"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	DEFAULT_CERTIFICATES_PATH = "certificates"
	DEFAULT_SUGGESTED_DNS     = "8.8.8.8"

	DEFAULT_ADMIN_KEYS           = ""
	DEFAULT_GRPC_MAX_TAIL_LENGTH = 256

	CLIENT_CERTIFICATE_NAME           = "SeasideVPN Whirlpool Server"
	CLIENT_CERTIFICATE_VALIDITY_YEARS = 1000
)

var (
	GRPC_MAX_TAIL_LENGTH = uint(utils.GetIntEnv("SEASIDE_GRPC_MAX_TAIL_LENGTH", DEFAULT_GRPC_MAX_TAIL_LENGTH, 32))
	SUGGESTED_DNS_SERVER = utils.GetEnv("SEASIDE_SUGGESTED_DNS", DEFAULT_SUGGESTED_DNS)
	CERTIFICATES_PATH    = utils.GetEnv("SEASIDE_CERTIFICATE_PATH", DEFAULT_CERTIFICATES_PATH)
)

// Metaserver structure.
// Contains gRPC server and whirlpool server, also includes connection listener.
type APIServer struct {
	// General purpose gRPC server.
	grpcServer *grpc.Server

	// gRPC connection listener.
	listener net.Listener
}

// Whirlpool server structure.
// Extends from generated gRPC Whirlpool server API.
// Contains all the data required for server execution.
type WhirlpoolServer struct {
	generated.UnimplementedWhirlpoolViridianServer

	address     net.IP
	apiPort     uint16
	portPort    uint16
	typhoonPort uint16
}

// Load and decode PEM certificate from file.
// Accept certificate path.
// Return certificate and nil if decoded successfully, nil and error otherwise.
func decodePEMCertificate(path string) (*x509.Certificate, error) {
	// Load certificate
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate: %v", err)
	}

	// Decode and parse certificate
	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %v", err)
	}

	// Return certificate
	return cert, nil
}

// Load and decode PEM elliptic curve key from file.
// Accept key path.
// Return key and nil if decoded successfully, nil and error otherwise.
func decodeECKey(path string) (any, error) {
	// Load key
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading key: %v", err)
	}

	// Decode and parse key or key
	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing key: %v", err)
	}

	// Return key
	return key, nil
}

// Load and generate client TLS credentials from files.
// Client certificate and key will be generated and signed using client certificate authoritiess.
// The client certificate authorities are expected to be in `${SEASIDE_CERTIFICATE_PATH}/APIclientCA.crt` and `${SEASIDE_CERTIFICATE_PATH}/APIclientCA.key`.
// Finally, server certificate and server CA are expected to be in `${SEASIDE_CERTIFICATE_PATH}/APIserverCA.crt` and `${SEASIDE_CERTIFICATE_PATH}/APIcert.crt`
func createClientTLSCredentials(address net.IP) ([]byte, []byte, []byte, error) {
	// Decode and parse client certificate authority certificate
	clientCACert, err := decodePEMCertificate(fmt.Sprintf("%s/APIclientCA.crt", CERTIFICATES_PATH))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error parsing client CA certificate: %v", err)
	}

	// Decode and parse client certificate authority key
	clientCAKey, err := decodeECKey(fmt.Sprintf("%s/APIclientCA.key", CERTIFICATES_PATH))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error parsing client CA key: %v", err)
	}

	// Generate a key for the new certificate
	private, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating a secp384r1 key for client certificate: %v", err)
	}

	// Generate certificate serial number
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error generating a serial number for client certificate: %v", err)
	}

	// Create a certificate template
	certificateCreationTime := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   CLIENT_CERTIFICATE_NAME,
			Organization: []string{address.String()},
		},
		NotBefore:   certificateCreationTime,
		NotAfter:    certificateCreationTime.AddDate(CLIENT_CERTIFICATE_VALIDITY_YEARS, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{address},
	}

	// Sign the certificate with the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, clientCACert, &private.PublicKey, clientCAKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating or signing client certificate: %v", err)
	}

	// Save the private key
	keyBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error marshalling client certificate key: %v", err)
	}

	// Decode and parse server certificate authority certificate
	serverCA, err := decodePEMCertificate(fmt.Sprintf("%s/APIserverCA.crt", CERTIFICATES_PATH))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error parsing server CA certificate: %v", err)
	}

	return serverCA.Raw, certBytes, keyBytes, nil
}

// Load server TLS credentials from files.
// Certificates are expected to be in `${SEASIDE_CERTIFICATE_PATH}/APIcert.crt` and `${SEASIDE_CERTIFICATE_PATH}/APIcert.key` files.
// Certificates should be valid and contain `subjectAltName` for the current `${SEASIDE_ADDRESS}`.
func loadServerTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate authority certificate
	caCertPEM, err := os.ReadFile(fmt.Sprintf("%s/APIclientCA.crt", CERTIFICATES_PATH))
	if err != nil {
		log.Fatalf("error reading client CA certificate: %v", err)
	}

	// Load certificate authority pool and add current CA certificate
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		log.Fatal("error adding client CA certificate")
	}

	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(fmt.Sprintf("%s/APIcert.crt", CERTIFICATES_PATH), fmt.Sprintf("%s/APIcert.key", CERTIFICATES_PATH))
	if err != nil {
		return nil, fmt.Errorf("error reading certificates: %v", err)
	}

	// Create the credentials and return it
	config := &tls.Config{
		ClientCAs:    certPool,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Return credentials
	return credentials.NewTLS(config), nil
}

func NewAPIServer(intAddress string, apiPort, portPort, typhoonPort uint16) (*APIServer, error) {
	// Create whirlpool server
	whirlpoolServer := WhirlpoolServer{
		address:     net.ParseIP(intAddress),
		apiPort:     apiPort,
		portPort:    portPort,
		typhoonPort: typhoonPort,
	}

	// Create TCP listener for gRPC connections
	apiAddress := fmt.Sprintf("%s:%d", intAddress, apiPort)
	listener, err := net.Listen("tcp", apiAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	// Load TLS credentials from files
	credentials, err := loadServerTLSCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials: %v", err)
	}

	// Create and start gRPC server
	grpcServer := grpc.NewServer(grpc.Creds(credentials))
	generated.RegisterWhirlpoolViridianServer(grpcServer, &whirlpoolServer)

	return &APIServer{
		grpcServer: grpcServer,
		listener:   listener,
	}, nil
}

// Run metaserver.
// Accept gRPC server and TCP connection listener.
func (server *APIServer) Start(ctx context.Context, wg *sync.WaitGroup, errorChan chan error) {
	defer wg.Done()

	logrus.Infof("Starting gRPC server on address: %v", server.listener.Addr())
	if err := server.grpcServer.Serve(server.listener); err != nil {
		select {
		case <-ctx.Done():
			return
		default:
			errorChan <- fmt.Errorf("failed to serve: %v", err)
		}
	}
}

// Stop metaserver.
// Should be applied for MetaServer object.
// Accept metaserver object pointer.
// Destroy gRPC and Whirlpool server, also close TCP listener.
func (server *APIServer) Stop() {
	server.grpcServer.GracefulStop()
}

func addMetadata(ctx context.Context) error {
	err := grpc.SetTrailer(ctx, metadata.Pairs("seaside-tail-bin", hex.EncodeToString(utils.GenerateReliableTail(GRPC_MAX_TAIL_LENGTH).Slice())))
	if err != nil {
		return fmt.Errorf("error adding metadata to the gRPC response: %v", err)
	} else {
		return nil
	}
}

// Authenticate viridian administrator.
// Check owner token, create user token and encrypt it with private key.
// Construct administrator certificate and send it.
// Should be applied for WhirlpoolServer object.
// Accept context and authentication request.
// Return authentication response and nil if authentication successful, otherwise nil and error.
func (server *WhirlpoolServer) AuthenticateAdmin(ctx context.Context, request *generated.WhirlpoolAdminAuthenticationRequest) (*generated.WhirlpoolAdminAuthenticationResponse, error) {
	// Decrypt admin token
	identityBytes, err := crypto.SERVER_KEY.Decrypt(betterbuf.NewBufferFromSlice(request.OwnerToken), nil)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "error decrypting owner token: %v", err)
	}

	// Create and decrypt admin token
	identity := &generated.AdminToken{}
	err = proto.Unmarshal(identityBytes.Slice(), identity)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "error parsing owner token: %v", err)
	}

	// Check if performed by owner
	if !identity.IsOwner {
		return nil, status.Error(codes.PermissionDenied, "admin can not add other admins")
	}

	// Log new token parameters
	logrus.Infof("Administrator %s authenticated by owner %s", request.Name, identity.Name)

	// Create and marshall user token
	token := &generated.AdminToken{
		Name:    request.Name,
		IsOwner: false,
	}
	marshToken, err := proto.Marshal(token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error marshalling token: %v", err)
	}

	// Encrypt token
	tokenData, err := crypto.SERVER_KEY.Encrypt(betterbuf.NewBufferFromCapacityEnsured(marshToken, crypto.NonceSize, crypto.MacSize), nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error encrypting token: %v", err)
	}

	// Create and load client credentials
	serverCA, clientCert, clientKey, err := createClientTLSCredentials(server.address)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error generating client certificate: %v", err)
	}

	// Create and marshall user certificate
	certificate := &generated.SeasideWhirlpoolAdminCertificate{
		Address:              server.address.String(),
		Port:                 uint32(server.apiPort),
		ClientCertificate:    clientCert,
		ClientKey:            clientKey,
		CertificateAuthority: serverCA,
		Token:                tokenData.Slice(),
	}

	// Create and marshall response
	err = addMetadata(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error adding metadata: %v", err)
	}
	return &generated.WhirlpoolAdminAuthenticationResponse{
		Certificate: certificate,
	}, nil
}

// Authenticate viridian client.
// Check administrator token, create user token and encrypt it with private key.
// Construct user certificate and send it.
// Should be applied for WhirlpoolServer object.
// Accept context and authentication request.
// Return authentication response and nil if authentication successful, otherwise nil and error.
func (server *WhirlpoolServer) AuthenticateClient(ctx context.Context, request *generated.WhirlpoolClientAuthenticationRequest) (*generated.WhirlpoolClientAuthenticationResponse, error) {
	// Decrypt admin token
	identityBytes, err := crypto.SERVER_KEY.Decrypt(betterbuf.NewBufferFromSlice(request.AdminToken), nil)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "error decrypting admin token: %v", err)
	}

	// Create and decrypt admin token
	identity := &generated.AdminToken{}
	err = proto.Unmarshal(identityBytes.Slice(), identity)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "error parsing admin token: %v", err)
	}

	// Log new token parameters
	logrus.Infof("User %s (id: %s) authenticated by administrator %s", request.Name, request.Identifier, identity.Name)

	// Create and marshall user token
	token := &generated.ClientToken{
		Name:         request.Name,
		Identifier:   request.Identifier,
		IsPrivileged: true,
		Subscription: request.Subscription,
	}
	marshToken, err := proto.Marshal(token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error marshalling token: %v", err)
	}

	// Encrypt token
	tokenData, err := crypto.SERVER_KEY.Encrypt(betterbuf.NewBufferFromCapacityEnsured(marshToken, crypto.NonceSize, crypto.MacSize), nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error encrypting token: %v", err)
	}

	// Create and marshall user certificate
	certificate := &generated.SeasideWhirlpoolClientCertificate{
		Address:       server.address.String(),
		TyphoonPublic: crypto.PRIVATE_KEY.PublicKey().Slice(),
		TyphoonPort:   uint32(server.typhoonPort),
		PortPort:      uint32(server.portPort),
		Token:         tokenData.Slice(),
		Dns:           SUGGESTED_DNS_SERVER,
	}

	// Create and marshall response
	err = addMetadata(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error adding metadata: %v", err)
	}
	return &generated.WhirlpoolClientAuthenticationResponse{
		Certificate: certificate,
	}, nil
}
