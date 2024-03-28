package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/qlog"
)

// const SERVER = "127.0.0.1"
// const SERVER = "192.168.1.79" // MacBook Pro M1 local IP
// const SERVER = "192.168.1.78" // wmnlab local IP
const SERVER = "140.112.20.183" // 249 public IP
const PORT_UL = 4200
const PORT_DL = 4201
const SLEEPTIME = 2

var serverAddr_ul string = fmt.Sprintf("%s:%d", SERVER, PORT_UL)
var serverAddr_dl string = fmt.Sprintf("%s:%d", SERVER, PORT_DL)

// const bufferMaxSize = 1048576          // 1mb
const PACKET_LEN = 250

func main() {

	keyLogFile := flag.String("keylog", "", "key log file")
	// insecure := flag.Bool("insecure", false, "skip certificate verification")
	flag.Parse()

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) { // capture packets in client side
			if i == 0 {
				var keyLog io.Writer
				if len(*keyLogFile) > 0 {
					f, err := os.Create(*keyLogFile)
					if err != nil {
						log.Fatal(err)
					}
					defer f.Close()
					keyLog = f
				}

				pool, err := x509.SystemCertPool()
				if err != nil {
					log.Fatal(err)
				}
				testdata.AddRootCA(pool)
				// set generate configs
				tlsConfig := &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h3"},
					RootCAs:            pool,
					KeyLogWriter:       keyLog,
				}
				quicConfig := GenQuicConfig(PORT_UL)

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
				defer cancel()
				// connect to server IP. Session is like the socket of TCP/IP
				session_ul, err := quic.DialAddr(ctx, serverAddr_ul, tlsConfig, &quicConfig)
				if err != nil {
					fmt.Println("err: ", err)
				}
				defer session_ul.CloseWithError(quic.ApplicationErrorCode(501), "hi you have an error")
				// create a stream_ul
				// context.Background() is similar to a channel, giving QUIC a way to communicate
				stream_ul, err := session_ul.OpenStreamSync(context.Background())
				if err != nil {
					log.Fatal(err)
				}
				defer stream_ul.Close()

				Client_send(stream_ul)
				session_ul.CloseWithError(0, "ul times up")
			} else {
				// set generate configs
				tlsConfig := GenTlsConfig()
				quicConfig := GenQuicConfig(PORT_DL)

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
				defer cancel()
				// connect to server IP. Session is like the socket of TCP/IP
				session_dl, err := quic.DialAddr(ctx, serverAddr_dl, tlsConfig, &quicConfig)
				if err != nil {
					fmt.Println("err: ", err)
				}
				defer session_dl.CloseWithError(quic.ApplicationErrorCode(501), "hi you have an error")
				// create a stream_dl
				// context.Background() is similar to a channel, giving QUIC a way to communicate
				stream_dl, err := session_dl.OpenStreamSync(context.Background())
				if err != nil {
					log.Fatal(err)
				}
				defer stream_dl.Close()

				// Open or create a file to store the floats in JSON format
				currentTime := time.Now()
				y := currentTime.Year()
				m := currentTime.Month()
				d := currentTime.Day()
				h := currentTime.Hour()
				n := currentTime.Minute()
				date := fmt.Sprintf("%02d%02d%02d", y, m, d)
				filepath := fmt.Sprintf("../data/time_%s_%02d%02d_%d.txt", date, h, n, PORT_DL)
				timeFile, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Println("Error opening file:", err)
					return
				}
				defer timeFile.Close()

				var message []byte
				t := time.Now().UnixNano() // Time in milliseconds
				fmt.Println("client create time: ", t)
				datetimedec := uint32(t / 1e9) // Extract seconds from milliseconds
				microsec := uint32(t % 1e9)    // Extract remaining microseconds
				message = append(message, make([]byte, 4)...)
				binary.BigEndian.PutUint32(message[:4], datetimedec)
				message = append(message, make([]byte, 4)...)
				binary.BigEndian.PutUint32(message[4:8], microsec)
				SendPacket(stream_dl, message)

				for {
					buf := make([]byte, PACKET_LEN)
					ts, err := Client_receive(stream_dl, buf)
					if ts == -115 {
						session_dl.CloseWithError(0, "dl times up")
					}
					if err != nil {
						return
					}
					fmt.Printf("client received: %f\n", ts)

					// Write the timestamp as a string to the text file
					_, err = timeFile.WriteString(fmt.Sprintf("%f\n", ts))
					if err != nil {
						fmt.Println("Error writing to file:", err)
						return
					}
				}
			}
		}(i)
	}
	wg.Wait()

}

func GenTlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		// RootCAs:            pool,
		// KeyLogWriter:       keyLog,
	}
}

func GenQuicConfig(port int) quic.Config {
	return quic.Config{
		Allow0RTT: true,
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
			filename := fmt.Sprintf("../data/log_%s_%02d%02d_%d_%s.qlog", date, h, n, port, role)
			f, err := os.Create(filename)
			if err != nil {
				fmt.Println("cannot generate qlog file")
			}
			// handle the error
			return qlog.NewConnectionTracer(f, p, connID)
		},
	}
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

func SendPacket(stream quic.Stream, message []byte) {
	_, err := stream.Write(message)
	if err != nil {
		log.Fatal(err)
	}
}

func Client_send(stream quic.Stream) {
	// Duration to run the sending process
	duration := 5 * time.Second
	seq := 1
	start_time := time.Now()
	euler := 271828
	pi := 31415926
	next_transmission_time := start_time.UnixMilli()
	for time.Since(start_time) <= time.Duration(duration) {
		for time.Now().UnixMilli() < next_transmission_time {
		}
		next_transmission_time += SLEEPTIME
		t := time.Now().UnixNano() // Time in milliseconds
		fmt.Println("client sent: ", t)
		datetimedec := uint32(t / 1e9) // Extract seconds from milliseconds
		microsec := uint32(t % 1e9)    // Extract remaining microseconds

		// var message []byte
		message := Create_packet(uint32(euler), uint32(pi), datetimedec, microsec, uint32(seq))
		SendPacket(stream, message)
		time.Sleep(500 * time.Millisecond)
		seq++
	}
}

func Client_receive(stream quic.Stream, buf []byte) (float64, error) {
	_, err := stream.Read(buf)
	tsSeconds := binary.BigEndian.Uint32(buf[8:12])
	tsMicroseconds := binary.BigEndian.Uint32(buf[12:16])
	var ts float64
	if tsSeconds == 115 && tsMicroseconds == 115 {
		return -115, err
	} else {
		ts = float64(tsSeconds) + float64(tsMicroseconds)/1e9
	}

	if err != nil {
		return -1103, err
	}

	return ts, err
}
