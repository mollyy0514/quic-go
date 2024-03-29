package main

// import (
// 	"context"
// 	"crypto/rand"
// 	"crypto/tls"
// 	"crypto/x509"
// 	"encoding/binary"
// 	"flag"
// 	"fmt"
// 	"io"
// 	"log"
// 	"os"
// 	"sync"
// 	"time"

// 	"github.com/quic-go/quic-go"
// 	"github.com/quic-go/quic-go/internal/testdata"
// 	"github.com/quic-go/quic-go/logging"
// 	"github.com/quic-go/quic-go/qlog"
// )

// // const Server = "127.0.0.1"
// // const Server = "192.168.1.79" // MacBook Pro M1 local IP
// // const Server = "192.168.1.78" // wmnlab local IP
// const Server = "140.112.20.183" // 249 public IP
// const PortUl = 4200
// const PortDL = 4201
// const SleepTime = 500

// var serverAddrUl string = fmt.Sprintf("%s:%d", Server, PortUl)
// var serverAddrDl string = fmt.Sprintf("%s:%d", Server, PortDL)

// // const bufferMaxSize = 1048576          // 1mb
// const PacketLen = 250

// func main() {
// 	_bind := flag.String("b", "", "interface to bind")
// 	flag.Parse()

// 	nowTime := time.Now()
// 	nowHour := nowTime.Hour()
// 	nowMinute := nowTime.Minute()
// 	var wg sync.WaitGroup
// 	wg.Add(2)
// 	for i := 0; i < 2; i++ {
// 		go func(i int) { // capture packets in client side
// 			if i == 0 {
// 				keyLogFileUl := fmt.Sprintf("../data/tls_key_%02d%02d_%02d.log", nowHour, nowMinute, PortUl)
// 				var keyLogUl io.Writer
// 				if len(keyLogFileUl) > 0 {
// 					f, err := os.Create(keyLogFileUl)
// 					if err != nil {
// 						log.Fatal(err)
// 					}
// 					defer f.Close()
// 					keyLogUl = f
// 				}

// 				poolUl, err := x509.SystemCertPool()
// 				if err != nil {
// 					log.Fatal(err)
// 				}
// 				testdata.AddRootCA(poolUl)
// 				tlsConfig := &tls.Config{
// 					InsecureSkipVerify: true,
// 					NextProtos:         []string{"h3"},
// 					RootCAs:            poolUl,
// 					KeyLogWriter:       keyLogUl,
// 				}
// 				// tlsConfig := GenTlsConfig(nowTime, PORT_UL)
// 				quicConfig := GenQuicConfig(PortUl)

// 				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
// 				defer cancel()
// 				// connect to server IP. Session is like the socket of TCP/IP
// 				sessionUl, err := quic.DialAddr(ctx, serverAddrUl, tlsConfig, &quicConfig, *_bind)
// 				if err != nil {
// 					fmt.Println("err: ", err)
// 				}
// 				defer sessionUl.CloseWithError(quic.ApplicationErrorCode(501), "hi you have an error")
// 				// create a streamUl
// 				// context.Background() is similar to a channel, giving QUIC a way to communicate
// 				streamUl, err := sessionUl.OpenStreamSync(context.Background())
// 				if err != nil {
// 					log.Fatal(err)
// 				}
// 				defer streamUl.Close()

// 				ClientSend(streamUl)
// 				sessionUl.CloseWithError(0, "ul times up")
// 			} else {
// 				// set generate configs
// 				keyLogFileDl := fmt.Sprintf("../data/tls_key_%02d%02d_%02d.log", nowHour, nowMinute, PortDL)
// 				var keyLogDl io.Writer
// 				if len(keyLogFileDl) > 0 {
// 					f, err := os.Create(keyLogFileDl)
// 					if err != nil {
// 						log.Fatal(err)
// 					}
// 					defer f.Close()
// 					keyLogDl = f
// 				}

// 				poolDl, err := x509.SystemCertPool()
// 				if err != nil {
// 					log.Fatal(err)
// 				}
// 				testdata.AddRootCA(poolDl)
// 				tlsConfig := &tls.Config{
// 					InsecureSkipVerify: true,
// 					NextProtos:         []string{"h3"},
// 					RootCAs:            poolDl,
// 					KeyLogWriter:       keyLogDl,
// 				}
// 				// tlsConfig := GenTlsConfig(nowTime, PORT_DL)
// 				quicConfig := GenQuicConfig(PortDL)

// 				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
// 				defer cancel()
// 				// connect to server IP. Session is like the socket of TCP/IP
// 				sessionDl, err := quic.DialAddr(ctx, serverAddrDl, tlsConfig, &quicConfig, *_bind)
// 				if err != nil {
// 					fmt.Println("err: ", err)
// 				}
// 				defer sessionDl.CloseWithError(quic.ApplicationErrorCode(501), "hi you have an error")
// 				// create a streamDl
// 				// context.Background() is similar to a channel, giving QUIC a way to communicate
// 				streamDl, err := sessionDl.OpenStreamSync(context.Background())
// 				if err != nil {
// 					log.Fatal(err)
// 				}
// 				defer streamDl.Close()

// 				// Open or create a file to store the floats in JSON format
// 				currentTime := time.Now()
// 				y := currentTime.Year()
// 				m := currentTime.Month()
// 				d := currentTime.Day()
// 				h := currentTime.Hour()
// 				n := currentTime.Minute()
// 				date := fmt.Sprintf("%02d%02d%02d", y, m, d)
// 				filepath := fmt.Sprintf("../data/time_%s_%02d%02d_%d.txt", date, h, n, PortDL)
// 				timeFile, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 				if err != nil {
// 					fmt.Println("Error opening file:", err)
// 					return
// 				}
// 				defer timeFile.Close()

// 				var message []byte
// 				t := time.Now().UnixNano() // Time in milliseconds
// 				fmt.Println("client create time: ", t)
// 				datetimedec := uint32(t / 1e9) // Extract seconds from milliseconds
// 				microsec := uint32(t % 1e9)    // Extract remaining microseconds
// 				message = append(message, make([]byte, 4)...)
// 				binary.BigEndian.PutUint32(message[:4], datetimedec)
// 				message = append(message, make([]byte, 4)...)
// 				binary.BigEndian.PutUint32(message[4:8], microsec)
// 				SendPacket(streamDl, message)

// 				for {
// 					buf := make([]byte, PacketLen)
// 					ts, err := ClientReceive(streamDl, buf)
// 					if ts == -115 {
// 						sessionDl.CloseWithError(0, "dl times up")
// 					}
// 					if err != nil {
// 						return
// 					}
// 					fmt.Printf("client received: %f\n", ts)

// 					// Write the timestamp as a string to the text file
// 					_, err = timeFile.WriteString(fmt.Sprintf("%f\n", ts))
// 					if err != nil {
// 						fmt.Println("Error writing to file:", err)
// 						return
// 					}
// 				}
// 			}
// 		}(i)
// 	}
// 	wg.Wait()

// }

// func GenTlsConfig() *tls.Config {
// 	return &tls.Config{
// 		InsecureSkipVerify: true,
// 		NextProtos:         []string{"h3"},
// 		// RootCAs:            pool,
// 		// KeyLogWriter:       keyLog,
// 	}
// }

// func GenQuicConfig(port int) quic.Config {
// 	return quic.Config{
// 		Allow0RTT: true,
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
// 			filename := fmt.Sprintf("../data/log_%s_%02d%02d_%d_%s.qlog", date, h, n, port, role)
// 			f, err := os.Create(filename)
// 			if err != nil {
// 				fmt.Println("cannot generate qlog file")
// 			}
// 			// handle the error
// 			return qlog.NewConnectionTracer(f, p, connID)
// 		},
// 	}
// }

// func CreatePacket(euler uint32, pi uint32, datetimedec uint32, microsec uint32, seq uint32) []byte {
// 	var message []byte
// 	message = append(message, make([]byte, 4)...)
// 	binary.BigEndian.PutUint32(message[:4], euler)
// 	message = append(message, make([]byte, 4)...)
// 	binary.BigEndian.PutUint32(message[4:8], pi)
// 	message = append(message, make([]byte, 4)...)
// 	binary.BigEndian.PutUint32(message[8:12], datetimedec)
// 	message = append(message, make([]byte, 4)...)
// 	binary.BigEndian.PutUint32(message[12:16], microsec)
// 	message = append(message, make([]byte, 4)...)
// 	binary.BigEndian.PutUint32(message[16:20], seq)

// 	// add random additional data to 250 bytes
// 	msgLength := len(message)
// 	if msgLength < PacketLen {
// 		randomBytes := make([]byte, PacketLen-msgLength)
// 		rand.Read(randomBytes)
// 		message = append(message, randomBytes...)
// 	}

// 	return message
// }

// func SendPacket(stream quic.Stream, message []byte) {
// 	_, err := stream.Write(message)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// }

// func ClientSend(stream quic.Stream) {
// 	// Duration to run the sending process
// 	duration := 5 * time.Second
// 	seq := 1
// 	startTime := time.Now()
// 	euler := 271828
// 	pi := 31415926
// 	nextTransmissionTime := startTime.UnixMilli()
// 	for time.Since(startTime) <= time.Duration(duration) {
// 		for time.Now().UnixMilli() < nextTransmissionTime {
// 		}
// 		nextTransmissionTime += SleepTime
// 		t := time.Now().UnixNano() // Time in milliseconds
// 		fmt.Println("client sent: ", t)
// 		datetimedec := uint32(t / 1e9) // Extract seconds from milliseconds
// 		microsec := uint32(t % 1e9)    // Extract remaining microseconds

// 		// var message []byte
// 		message := CreatePacket(uint32(euler), uint32(pi), datetimedec, microsec, uint32(seq))
// 		SendPacket(stream, message)
// 		seq++
// 	}
// }

// func ClientReceive(stream quic.Stream, buf []byte) (float64, error) {
// 	_, err := stream.Read(buf)
// 	tsSeconds := binary.BigEndian.Uint32(buf[8:12])
// 	tsMicroseconds := binary.BigEndian.Uint32(buf[12:16])
// 	var ts float64
// 	if tsSeconds == 115 && tsMicroseconds == 115 {
// 		return -115, err
// 	} else {
// 		ts = float64(tsSeconds) + float64(tsMicroseconds)/1e9
// 	}

// 	if err != nil {
// 		return -1103, err
// 	}

// 	return ts, err
// }
