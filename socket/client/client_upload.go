package main

// import (
// 	"bufio"
// 	"context"
// 	"crypto/tls"
// 	"flag"
// 	"fmt"
// 	"io"
// 	"log"
// 	"os"
// 	"strconv"
// 	"sync"
// 	"time"

// 	"github.com/quic-go/quic-go"
// 	"github.com/quic-go/quic-go/logging"
// 	"github.com/quic-go/quic-go/qlog"
// )

// // var SERVER = "127.0.0.1"
// // var SERVER = "192.168.1.79" // MacBook Pro M1 local IP
// // var SERVER = "192.168.1.78" // wmnlab local IP
// // var SERVER = "140.112.20.183" // 249 public IP
// var SERVER string
// var PORT_UL int
// var serverAddr_ul string
// const PACKET_LEN = 250

// func main() {
// 	_host := flag.String("h", "127.0.0.1", "server ip")
// 	_port := flag.Int("p", 4200, "server upload port")
// 	_file := flag.String("f", "input.txt", "the file name that we need to transfer")
// 	flag.Parse()
// 	SERVER = *_host
// 	PORT_UL = *_port
// 	file := *_file
// 	serverAddr_ul = fmt.Sprintf("%s:%d", SERVER, PORT_UL)

// 	var wg sync.WaitGroup
// 	wg.Add(1)
// 	for i := 0; i < 1; i++ {
// 		go func(i int) { // capture packets in client side
// 			if i == 0 {
// 				// set generate configs
// 				tlsConfig := GenTlsConfig()
// 				quicConfig := GenQuicConfig(PORT_UL)

// 				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second) // 3s handshake timeout
// 				defer cancel()
// 				// connect to server IP. Session is like the socket of TCP/IP
// 				session_ul, err := quic.DialAddr(ctx, serverAddr_ul, tlsConfig, &quicConfig)
// 				if err != nil {
// 					fmt.Println("err: ", err)
// 				}
// 				defer session_ul.CloseWithError(quic.ApplicationErrorCode(501), "hi you have an error")
// 				// create a stream_ul
// 				// context.Background() is similar to a channel, giving QUIC a way to communicate
// 				stream_ul, err := session_ul.OpenStreamSync(context.Background())
// 				if err != nil {
// 					log.Fatal(err)
// 				}
// 				defer stream_ul.Close()

// 				data, name, size := ReadFile(file)
// 				Client_send_file(stream_ul, name, size)
// 				fmt.Printf("upload %s with %d bytes\n", name, size)
// 				// if size > 4096*1024 {
// 				// 	fmt.Println("size: ", size)
// 				// }
// 				sendBytes, err := io.Copy(stream_ul, data)
// 				if err != nil {
// 					log.Fatalf("write stream error: %v\n", err)
// 				}
// 				fmt.Printf("send %d bytes\n", sendBytes)
// 				time.Sleep(time.Second * 1)
// 				stream_ul.Close()
// 				session_ul.CloseWithError(0, "ul times up")
// 				os.Exit(0)
// 			}
// 		}(i)
// 	}
// 	wg.Wait()

// }

// func GenTlsConfig() *tls.Config {
// 	return &tls.Config{
// 		InsecureSkipVerify: true,
// 		NextProtos:         []string{"h3"},
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
// 			filename := fmt.Sprintf("./log_%s_%02d%02d_%d_%s.qlog", date, h, n, port, role)
// 			f, err := os.Create(filename)
// 			if err != nil {
// 				fmt.Println("cannot generate qlog file")
// 			}
// 			// handle the error
// 			return qlog.NewConnectionTracer(f, p, connID)
// 		},
// 	}
// }

// func ReadFile(file string) (*bufio.Reader, string, int64) {
// 	fp, err := os.Open(file)
// 	if err != nil {
// 		log.Fatalf("open file error: %v\n", err)
// 	}
// 	fileInfo, err := fp.Stat()
// 	if err != nil {
// 		log.Fatalf("get file info error: %v\n", err)
// 	}
// 	// fmt.Printf("Name: %v \n", fileInfo.Name())
// 	// fmt.Printf("Size: %v \n", fileInfo.Size())
// 	// fmt.Printf("Mode: %v \n", fileInfo.Mode())
// 	// fmt.Printf("ModTime: %v \n", fileInfo.ModTime())
// 	// fmt.Printf("IsDir: %v \n", fileInfo.IsDir())
// 	// fmt.Printf("Sys: %#v \n", fileInfo.Sys())
// 	return bufio.NewReader(fp), fileInfo.Name(), fileInfo.Size()
// }

// func Create_packet(fileName string, fileSize int64) []byte {
// 	fileSizeStr := strconv.FormatInt(fileSize, 10)
// 	sendString := fileName + "@" + fileSizeStr
// 	message := []byte(sendString)

// 	return message
// }

// func SendPacket(stream quic.Stream, message []byte) {
// 	_, err := stream.Write(message)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// }

// func Client_send_file(stream quic.Stream, name string, size int64) {
// 	t := time.Now().UnixNano() // Time in milliseconds
// 	fmt.Println("client sent: ", t)

// 	message := Create_packet(name, size)
// 	SendPacket(stream, message)
// }
