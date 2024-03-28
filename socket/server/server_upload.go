package main

// import (
// 	"bufio"
// 	"context"
// 	"crypto/rand"
// 	"crypto/rsa"
// 	"crypto/tls"
// 	"crypto/x509"
// 	"encoding/pem"
// 	"flag"
// 	"fmt"
// 	"io"
// 	"log"
// 	"math/big"
// 	"os"
// 	"strconv"
// 	"strings"
// 	"sync"
// 	"time"

// 	"github.com/quic-go/quic-go"
// 	"github.com/quic-go/quic-go/logging"
// 	"github.com/quic-go/quic-go/qlog"
// )

// var SERVER string
// var PORT_UL int
// var DESTDIR string
// const PACKET_LEN = 250

// // We start a server echoing data on the first stream the client opens,
// // then connect with a client, send the message, and wait for its receipt.
// func main() {
// 	_host := flag.String("h", "0.0.0.0", "host")
// 	_port := flag.Int("p", 4200, "server upload port")
// 	_dest := flag.String("d", "/Users/molly/Desktop/", "where to put the received files")
// 	flag.Parse()
// 	SERVER = *_host
// 	DESTDIR = *_dest
// 	PORT_UL = *_port

// 	// Check if the directory already exists
//     if _, err := os.Stat(DESTDIR); os.IsNotExist(err) {
//         // Create the directory and its parent directories if they do not exist
//         if err := os.MkdirAll(DESTDIR, 0755); err != nil {
//             print("Directory create error: %v", err)
//         }
//     }

// 	fmt.Println("Starting server...")

// 	var wg sync.WaitGroup
// 	wg.Add(1)
// 	defer wg.Done()
// 	for i := 0; i < 1; i++ {
// 		go EchoQuicServer(SERVER, PORT_UL, true)
// 		// go EchoQuicServer(SERVER, PORT_DL, false)
// 	}
// 	wg.Wait()
// }

// func HandleQuicStream_ul(stream quic.Stream) {
// 	fileNameBuf := make([]byte, PACKET_LEN)
// 	filename, filesize, err := Server_receive_file(stream, fileNameBuf)
// 	if err != nil {
// 		return
// 	}
// 	fmt.Printf("Received: %s %d bytes\n", filename, filesize)

// 	buf, err := WriteFile(DESTDIR + filename)
// 	if err != nil {
// 		log.Printf("open file error: %v\n", err)
// 		// continue
// 	}
// 	recvByte, err := io.Copy(buf, stream)
// 	buf.Flush()
// 	if err != nil {
// 		log.Printf("write file error: %v\n", err)
// 	}
// 	log.Printf("recv %d bytes\n", recvByte)

// 	if filesize != recvByte {
// 		log.Printf("size error occur: want %d, received %d \n", filesize, recvByte)
// 	}
// }

// func HandleQuicSession(sess quic.Connection) {
// 	for {
// 		// create a stream to receive message, and also create a channel for communication
// 		stream, err := sess.AcceptStream(context.Background())
// 		if err != nil {
// 			fmt.Println(err)
// 			return // Using panic here will terminate the program if a new connection has not come in in a while, such as transmitting large file.
// 		}

// 		go HandleQuicStream_ul(stream)
// 	}
// }

// // Start a server that echos all data on top of QUIC
// func EchoQuicServer(host string, quicPort int, ul bool) error {
// 	// Start_server_tcpdump(quicPort)
// 	nowTime := time.Now()
// 	quicConfig := quic.Config{
// 		KeepAlivePeriod: time.Minute * 5,
// 		EnableDatagrams: true,
// 		Allow0RTT:       true,
// 		Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
// 			role := "server"
// 			if p == logging.PerspectiveClient {
// 				role = "client"
// 			}
// 			currentTime := time.Now()
// 			y := currentTime.Year()
// 			m := currentTime.Month()
// 			d := currentTime.Day()
// 			h := currentTime.Hour()
// 			n := currentTime.Minute()
// 			date := fmt.Sprintf("%02d%02d%02d", y, m, d)
// 			filename := fmt.Sprintf("./log_%s_%02d%02d_%d_%s.qlog", date, h, n, quicPort, role)
// 			f, err := os.Create(filename)
// 			if err != nil {
// 				fmt.Println("cannot generate qlog file")
// 			}
// 			// handle the error
// 			return qlog.NewConnectionTracer(f, p, connID)
// 		},
// 	}
// 	// ListenAddrEarly supports 0rtt
// 	listener, err := quic.ListenAddr(fmt.Sprintf("%s:%d", host, quicPort), GenerateTLSConfig(nowTime, quicPort), &quicConfig)
// 	if err != nil {
// 		return err
// 	}

// 	fmt.Printf("Started QUIC server! %s:%d\n", host, quicPort)

// 	for {
// 		// create a session
// 		sess, err := listener.Accept(context.Background())
// 		fmt.Printf("Accepted Connection! %s\n", sess.RemoteAddr())
// 		if err != nil {
// 			return err
// 		}

// 		go HandleQuicSession(sess)
// 	}
// }

// // Setup a bare-bones TLS config for the server
// func GenerateTLSConfig(nowTime time.Time, port int) *tls.Config {
// 	key, err := rsa.GenerateKey(rand.Reader, 1024)
// 	if err != nil {
// 		panic(err)
// 	}
// 	template := x509.Certificate{SerialNumber: big.NewInt(1)}
// 	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
// 	if err != nil {
// 		panic(err)
// 	}
// 	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
// 	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

// 	nowHour := nowTime.Hour()
// 	nowMinute := nowTime.Minute()
// 	keyFilePath := fmt.Sprintf("../data/tls_key_%02d%02d_%02d.log", nowHour, nowMinute, port)
// 	kl, _ := os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)

// 	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return &tls.Config{
// 		Certificates: []tls.Certificate{tlsCert},
// 		NextProtos:   []string{"h3"},
// 		KeyLogWriter: kl,
// 	}
// }

// func Server_receive_dir(stream quic.Stream, buf []byte) (string) {
// 	n, err := stream.Read(buf)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	dirName := string(buf[:n])

// 	return dirName
// }

// func Server_receive_file(stream quic.Stream, buf []byte) (string, int64, error) {
// 	n, err := stream.Read(buf)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	packetData := string(buf[:n])
// 	parts := strings.Split(packetData, "@")

// 	// Extract fileName and fileSizeStr
// 	fileName := parts[0]
// 	fileSizeStr := parts[1]
// 	fileSize, err := strconv.ParseInt(fileSizeStr, 10, 64)

// 	return fileName, fileSize, err
// }

// func WriteFile(file string) (*bufio.Writer, error) {
// 	fp, err := os.Create(file)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return bufio.NewWriter(fp), nil
// }
