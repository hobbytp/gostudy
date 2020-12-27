package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes"
}

// Config for Vault prototyping purpose
const (
	jwtPath              = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caCertPath           = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	certExpirationBuffer = time.Minute
)

var serverCaLog = log.RegisterScope("serverca", "Citadel server log", 0)

// CertificateAuthority contains methods to be supported by a CA.
type CertificateAuthority interface {
	// Sign generates a certificate for a workload or CA, from the given CSR and TTL.
	// TODO(myidpt): simplify this interface and pass a struct with cert field values instead.
	Sign(csrPEM []byte, subjectIDs []string, ttl time.Duration, forCA bool) ([]byte, error)
	// SignWithCertChain is similar to Sign but returns the leaf cert and the entire cert chain.
	SignWithCertChain(csrPEM []byte, subjectIDs []string, ttl time.Duration, forCA bool) ([]byte, error)
	// GetCAKeyCertBundle returns the KeyCertBundle used by CA.
	GetCAKeyCertBundle() util.KeyCertBundle
}

// Server implements IstioCAService and IstioCertificateService and provides the services on the
// specified port.
type Server struct {
	monitoring     monitoringMetrics
	//Authenticators []authenticate.Authenticator
	hostnames      []string
	ca             CertificateAuthority
	serverCertTTL  time.Duration
	certificate    *tls.Certificate
	port           int
	forCA          bool
	grpcServer     *grpc.Server
}

func (s *Server) createTLSServerOption() grpc.ServerOption {
	cp := x509.NewCertPool()
	rootCertBytes := s.ca.GetCAKeyCertBundle().GetRootCertPem()
	cp.AppendCertsFromPEM(rootCertBytes)

	config := &tls.Config{
		ClientCAs:  cp,
		ClientAuth: tls.VerifyClientCertIfGiven,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if s.certificate == nil || shouldRefresh(s.certificate) {
				// Apply new certificate if there isn't one yet, or the one has become invalid.
				newCert, err := s.getServerCertificate()
				if err != nil {
					return nil, fmt.Errorf("failed to apply TLS server certificate (%v)", err)
				}
				s.certificate = newCert
			}
			return s.certificate, nil
		},
	}
	return grpc.Creds(credentials.NewTLS(config))
}

func (s *Server) Run() error {
	grpcServer := s.grpcServer
	var listener net.Listener
	var err error

	if grpcServer == nil {
		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
		if err != nil {
			return fmt.Errorf("cannot listen on port %d (error: %v)", s.port, err)
		}

		var grpcOptions []grpc.ServerOption
		grpcOptions = append(grpcOptions, s.createTLSServerOption(), grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor))

		grpcServer = grpc.NewServer(grpcOptions...)
	}
	//Hobby commented
	//pb.RegisterIstioCertificateServiceServer(grpcServer, s)

	grpc_prometheus.EnableHandlingTimeHistogram()
	grpc_prometheus.Register(grpcServer)

	if listener != nil {
		// grpcServer.Serve() is a blocking call, so run it in a goroutine.
		go func() {
			serverCaLog.Infof("Starting GRPC server on port %d", s.port)

			err := grpcServer.Serve(listener)

			// grpcServer.Serve() always returns a non-nil error.
			serverCaLog.Warnf("GRPC server returns an error: %v", err)
		}()
	}

	return nil
}

func detectAuthEnv(jwt string) (*authenticate.JwtPayload, error) {
	jwtSplit := strings.Split(jwt, ".")
	if len(jwtSplit) != 3 {
		return nil, fmt.Errorf("invalid JWT parts: %s", jwt)
	}
	payload := jwtSplit[1]

	payloadBytes, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt: %v", err.Error())
	}

	structuredPayload := &authenticate.JwtPayload{}
	err = json.Unmarshal(payloadBytes, &structuredPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt: %v", err.Error())
	}

	return structuredPayload, nil
}