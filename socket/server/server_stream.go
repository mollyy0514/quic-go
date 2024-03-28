package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"sync"
	"time"
	"fmt"
	"log"
	"math/big"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

// const bufferMaxSize = 1048576 // 1mb
const PACKET_LEN = 250
const SERVER = "0.0.0.0"
const PORT_UL = 4200
const PORT_DL = 4201
const SLEEPTIME = 2

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	fmt.Println("Starting server...")

	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Done()
	for i := 0; i < 2; i++ {
		go EchoQuicServer(SERVER, PORT_UL, true)
		go EchoQuicServer(SERVER, PORT_DL, false)
	}
	wg.Wait()
}

func HandleQuicStream_ul(stream quic.Stream) {
	// Open or create a file to store the floats in JSON format
	currentTime := time.Now()
	y := currentTime.Year()
	m := currentTime.Month()
	d := currentTime.Day()
	h := currentTime.Hour()
	n := currentTime.Minute()
	date := fmt.Sprintf("%02d%02d%02d", y, m, d)
	filepath := fmt.Sprintf("../data/time_%s_%02d%02d_%d.txt", date, h, n, PORT_UL)
	timeFile, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer timeFile.Close()

	for {
		buf := make([]byte, PACKET_LEN)
		ts, err := Server_receive(stream, buf)
		if err != nil {
			return
		}
		fmt.Printf("Received: %f\n", ts)

		// Write the timestamp as a string to the text file
		_, err = timeFile.WriteString(fmt.Sprintf("%f\n", ts))
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
}

func HandleQuicStream_dl(stream quic.Stream) {
	duration := 5 * time.Second
	seq := 1
	start_time := time.Now()
	euler := 271828
	pi := 31415926
	next_transmission_time := start_time.UnixMilli()
	for time.Since(start_time) <= time.Duration(duration) {
		for time.Now().UnixMilli() < next_transmission_time {}
		next_transmission_time += SLEEPTIME
		t := time.Now().UnixNano() // Time in milliseconds
		fmt.Println("server sent:", t)
		datetimedec := uint32(t / 1e9) // Extract seconds from milliseconds
		microsec := uint32(t % 1e9)    // Extract remaining microseconds

		// var message []byte
		message := Create_packet(uint32(euler), uint32(pi), datetimedec, microsec, uint32(seq))
		Transmit(stream, message)
		time.Sleep(500 * time.Millisecond)
		seq++
	}
	// the last packet to tell client to close the session
	message := Create_packet(uint32(euler), uint32(pi), 115, 115, uint32(seq))
	Transmit(stream, message)
}

func HandleQuicSession(sess quic.Connection, ul bool) {
	for {
		// create a stream to receive message, and also create a channel for communication
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			fmt.Println(err)
			return // Using panic here will terminate the program if a new connection has not come in in a while, such as transmitting large file.
		}
		if ul {
			go HandleQuicStream_ul(stream)
		} else {
			go HandleQuicStream_dl(stream)
		}
	}
}

// Start a server that echos all data on top of QUIC
func EchoQuicServer(host string, quicPort int, ul bool) error {
	// Start_server_tcpdump(quicPort)
	nowTime := time.Now()
	quicConfig := quic.Config{
		KeepAlivePeriod: time.Minute * 5,
		EnableDatagrams: true,
		Allow0RTT:       true,
		Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			role := "server"
			if p == logging.PerspectiveClient {
				role = "client"
			}
			currentTime := time.Now()
			y := currentTime.Year()
			m := currentTime.Month()
			d := currentTime.Day()
			h := currentTime.Hour()
			n := currentTime.Minute()
			date := fmt.Sprintf("%02d%02d%02d", y, m, d)
			filename := fmt.Sprintf("../data/log_%s_%02d%02d_%d_%s.qlog", date, h, n, quicPort, role)
			f, err := os.Create(filename)
			if err != nil {
				fmt.Println("cannot generate qlog file")
			}
			// handle the error
			return qlog.NewConnectionTracer(f, p, connID)
		},
	}
	// ListenAddrEarly supports 0rtt
	listener, err := quic.ListenAddr(fmt.Sprintf("%s:%d", host, quicPort), GenerateTLSConfig(nowTime, quicPort), &quicConfig)
	if err != nil {
		return err
	}

	fmt.Printf("Started QUIC server! %s:%d\n", host, quicPort)

	for {
		// create a session
		sess, err := listener.Accept(context.Background())
		fmt.Printf("Accepted Connection! %s\n", sess.RemoteAddr())
		if err != nil {
			return err
		}

		go HandleQuicSession(sess, ul)
	}
}

// Setup a bare-bones TLS config for the server
func GenerateTLSConfig(nowTime time.Time, port int) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	nowHour := nowTime.Hour()
	nowMinute := nowTime.Minute()
	keyFilePath := fmt.Sprintf("../data/tls_key_%02d%02d_%02d.log", nowHour, nowMinute, port)
	kl, _ := os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3"},
		KeyLogWriter: kl,
	}
}

func Server_receive(stream quic.Stream, buf []byte) (float64, error) {
	_, err := stream.Read(buf)
	tsSeconds := binary.BigEndian.Uint32(buf[8:12])
	tsMicroseconds := binary.BigEndian.Uint32(buf[12:16])
	ts := float64(tsSeconds) + float64(tsMicroseconds)/1e9
	if err != nil {
		return -115, err
	}
	return ts, err
}

func Create_packet(euler uint32, pi uint32, datetimedec uint32, microsec uint32, seq uint32) []byte {
	var message []byte
	message = append(message, make([]byte, 4)...)
	binary.BigEndian.PutUint32(message[:4], euler)
	message = append(message, make([]byte, 4)...)
	binary.BigEndian.PutUint32(message[4:8], pi)
	message = append(message, make([]byte, 4)...)
	binary.BigEndian.PutUint32(message[8:12], datetimedec)
	message = append(message, make([]byte, 4)...)
	binary.BigEndian.PutUint32(message[12:16], microsec)
	message = append(message, make([]byte, 4)...)
	binary.BigEndian.PutUint32(message[16:20], seq)

	// add random additional data to 250 bytes
	msgLength := len(message)
	if msgLength < PACKET_LEN {
		randomBytes := make([]byte, PACKET_LEN-msgLength)
		rand.Read(randomBytes)
		message = append(message, randomBytes...)
	}

	return message
}

func Transmit(stream quic.Stream, message []byte) {
	_, err := stream.Write(message)
	if err != nil {
		log.Fatal(err)
	}
}
