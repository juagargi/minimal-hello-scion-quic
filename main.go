package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

const (
	modeServer = "server"
	modeClient = "client"

	localIP    = "127.0.0.1"
	serverPort = 40000
	alpnProto  = "minimal-scion-quic"
	message    = "hello quic over scion"
)

func main() {
	var mode string
	var remote string

	flag.StringVar(&mode, "mode", "", "mode: server or client")
	flag.StringVar(&remote, "remote", "", "server address for client mode, e.g. 1-ff00:0:111,127.0.0.1:40000")
	flag.Parse()

	switch mode {
	case modeServer:
		if err := runServer(); err != nil {
			log.Fatalf("server failed: %v", err)
		}
	case modeClient:
		if remote == "" {
			log.Fatal("client mode requires -remote")
		}
		if err := runClient(remote); err != nil {
			log.Fatalf("client failed: %v", err)
		}
	default:
		log.Fatal(`-mode must be "server" or "client"`)
	}
}

func runServer() error {
	ctx := context.Background()

	sd, err := connectDaemon(ctx)
	if err != nil {
		return err
	}
	defer sd.Close()

	topo, err := daemon.LoadTopology(ctx, sd)
	if err != nil {
		return fmt.Errorf("loading topology: %w", err)
	}

	localAddr := &net.UDPAddr{IP: net.ParseIP(localIP), Port: serverPort}
	network := &snet.SCIONNetwork{Topology: topo}
	conn, err := network.Listen(ctx, "udp", localAddr)
	if err != nil {
		return fmt.Errorf("opening SCION socket: %w", err)
	}
	defer conn.Close()

	tlsConf, err := generateTLSConfig()
	if err != nil {
		return fmt.Errorf("generating TLS config: %w", err)
	}
	listener, err := quic.Listen(conn, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("starting QUIC listener: %w", err)
	}
	defer listener.Close()

	log.Printf("server listening on %s via daemon %s", conn.LocalAddr(), daemonAddress())

	for {
		session, err := listener.Accept(ctx)
		if err != nil {
			return fmt.Errorf("accepting QUIC connection: %w", err)
		}
		log.Printf("accepted QUIC connection from %s", session.RemoteAddr())
		go handleSession(session)
	}
}

func handleSession(session *quic.Conn) {
	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			log.Printf("session %s closed: %v", session.RemoteAddr(), err)
			return
		}
		go handleStream(session.RemoteAddr(), stream)
	}
}

func handleStream(remote net.Addr, stream *quic.Stream) {
	defer stream.Close()

	payload, err := io.ReadAll(stream)
	if err != nil {
		log.Printf("reading stream from %s: %v", remote, err)
		return
	}
	log.Printf("echoing to %s: %q", remote, string(payload))

	if _, err := (*stream).Write(payload); err != nil {
		log.Printf("writing stream to %s: %v", remote, err)
	}
}

func runClient(remoteStr string) error {
	ctx := context.Background()

	sd, err := connectDaemon(ctx)
	if err != nil {
		return err
	}
	defer sd.Close()

	topo, err := daemon.LoadTopology(ctx, sd)
	if err != nil {
		return fmt.Errorf("loading topology: %w", err)
	}
	localIA, err := sd.LocalIA(ctx)
	if err != nil {
		return fmt.Errorf("loading local IA: %w", err)
	}

	remote, selectedPath, err := prepareRemote(ctx, sd, localIA, remoteStr)
	if err != nil {
		return err
	}

	network := &snet.SCIONNetwork{Topology: topo}
	localAddr := &net.UDPAddr{IP: net.ParseIP(localIP), Port: 0}
	conn, err := network.Listen(ctx, "udp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local SCION socket: %w", err)
	}
	defer conn.Close()

	tlsConf, err := generateTLSConfig()
	if err != nil {
		return fmt.Errorf("generating TLS config: %w", err)
	}
	tlsConf.InsecureSkipVerify = true

	transport := &quic.Transport{Conn: conn}
	defer transport.Close()

	session, err := transport.Dial(ctx, remote, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("dialing QUIC session to %s: %w", remote, err)
	}
	defer session.CloseWithError(0, "")

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("opening QUIC stream: %w", err)
	}

	if _, err := stream.Write([]byte(message)); err != nil {
		return fmt.Errorf("writing request: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("closing write side: %w", err)
	}

	reply, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	log.Printf("selected remote %s", remote)
	if selectedPath != nil && selectedPath.Metadata() != nil {
		log.Printf("selected path %s", selectedPath.Metadata().Fingerprint())
	}
	fmt.Println(string(reply))
	return nil
}

func connectDaemon(ctx context.Context) (daemon.Connector, error) {
	sd, err := daemon.NewService(daemonAddress()).Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to daemon at %s: %w", daemonAddress(), err)
	}
	return sd, nil
}

func daemonAddress() string {
	if address := os.Getenv("SCION_DAEMON_ADDRESS"); address != "" {
		return address
	}
	return daemon.DefaultAPIAddress
}

func prepareRemote(
	ctx context.Context,
	sd daemon.Connector,
	localIA addr.IA,
	remoteStr string,
) (*snet.UDPAddr, snet.Path, error) {
	remote, err := snet.ParseUDPAddr(remoteStr)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing remote address: %w", err)
	}
	if remote.Host == nil || remote.Host.Port == 0 {
		return nil, nil, fmt.Errorf("remote address must include a UDP port")
	}
	if remote.IA == localIA {
		remote.Path = snetpath.Empty{}
		remote.NextHop = nil
		return remote, nil, nil
	}

	paths, err := sd.Paths(ctx, remote.IA, localIA, daemontypes.PathReqFlags{})
	if err != nil {
		return nil, nil, fmt.Errorf("querying paths to %s: %w", remote.IA, err)
	}
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("no path to %s", remote.IA)
	}

	selected := paths[0]
	remote.Path = selected.Dataplane()
	remote.NextHop = selected.UnderlayNextHop()
	return remote, selected, nil
}

func generateTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "minimal-scion-quic",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{alpnProto},
	}, nil
}
