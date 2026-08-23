// by Ori & Funsy
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	uquic "github.com/refraction-networking/uquic"
	uhttp3 "github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
)

const version = "0.0.1"

var (
	tcpListenerReady   = make(chan bool)
	udpListenerReady   = make(chan bool)
	tcpListenerQuitted = make(chan bool)
	udpListenerQuitted = make(chan bool)

	browsers_TLS_CH       = browsers_TLS_CH_type{}
	browsers_QUIC_Initial = browsers_QUIC_Initial_type{}
	protocols_TLS         = protocols_TLS_type{}

	cropAt int
	SNI    string

	loopbackPort = 4343
	defaultSNI   = "fonts.google.com"
)

type browsers_TLS_CH_type []struct {
	name            string
	utls_pointer    *utls.ClientHelloID
	additional_info string
}

func (b *browsers_TLS_CH_type) add(_name string, _ptr *utls.ClientHelloID, _info string) {
	*b = append(*b, struct {
		name            string
		utls_pointer    *utls.ClientHelloID
		additional_info string
	}{name: _name, utls_pointer: _ptr, additional_info: _info})
}

func (b *browsers_TLS_CH_type) getID(_name string) int {
	for n, each := range *b {
		if each.name == _name {
			return n
		}
	}
	return -1
}

type browsers_QUIC_Initial_type []struct {
	name            string
	uquic_pointer   *uquic.QUICID
	additional_info string
}

func (b *browsers_QUIC_Initial_type) add(_name string, _ptr *uquic.QUICID, _info string) {
	*b = append(*b, struct {
		name            string
		uquic_pointer   *uquic.QUICID
		additional_info string
	}{name: _name, uquic_pointer: _ptr, additional_info: _info})
}

func (b *browsers_QUIC_Initial_type) getID(_name string) int {
	for n, each := range *b {
		if each.name == _name {
			return n
		}
	}
	return -1
}

type protocols_TLS_type []struct {
	name            string
	id              int
	additional_info string
	filename        string
}

func (p *protocols_TLS_type) add(_name string, _id int, _info string, _filename string) {
	*p = append(*p, struct {
		name            string
		id              int
		additional_info string
		filename        string
	}{name: _name, id: _id, additional_info: _info, filename: _filename})
}

func (p *protocols_TLS_type) getID(_name string) int {
	for n, each := range *p {
		if each.name == _name {
			return n
		}
	}
	return -1
}

func init() {
	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32

	if err := windows.GetConsoleMode(stdout, &mode); err == nil {
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
		_ = windows.SetConsoleMode(stdout, mode)
	}

	browsers_TLS_CH.add("Firefox 120", &utls.HelloFirefox_120, "")
	browsers_TLS_CH.add("Chrome 102", &utls.HelloChrome_102, "")
	browsers_TLS_CH.add("Chrome 106 (Shuffle)", &utls.HelloChrome_106_Shuffle, "Chrome added TLS extension shuffler")
	browsers_TLS_CH.add("Chrome 112 (PSK, Shuffle)", &utls.HelloChrome_112_PSK_Shuf, "Chrome added Pre-shared Key extension, but uTLS doesn't have full support for it")
	browsers_TLS_CH.add("Chrome 115 (PQ)", &utls.HelloChrome_115_PQ, "Chrome added Post-Quantum Key Agreement extension, but uTLS doesn't have full support for it")
	browsers_TLS_CH.add("Chrome 120 (ECH)", &utls.HelloChrome_120, "Chrome added Encrypted ClientHello")
	browsers_TLS_CH.add("Chrome 120 (ECH, PQ)", &utls.HelloChrome_120_PQ, "")
	browsers_TLS_CH.add("Chrome 131 (ML-KEM curve)", &utls.HelloChrome_131, "Chrome added Module-Lattice Key Encapsulation Mechanism a.k.a. Kyber")
	browsers_TLS_CH.add("Android 11", &utls.HelloAndroid_11_OkHttp, "")
	browsers_TLS_CH.add("Edge 85", &utls.HelloEdge_85, "")
	browsers_TLS_CH.add("Edge 106", &utls.HelloEdge_106, "Edge 106 seems to be incompatible with uTLS library, according to them")
	browsers_TLS_CH.add("Safari 16.0", &utls.HelloSafari_16_0, "")
	browsers_TLS_CH.add("Random ALPN", &utls.HelloRandomizedALPN, "Randomize fields, use Application-Layer Protocol Negotiation TLS extension")
	browsers_TLS_CH.add("Random", &utls.HelloRandomizedNoALPN, "Randomize fields")

	browsers_QUIC_Initial.add("Firefox 116 (A)", &uquic.QUICFirefox_116A, "Destination Connection ID length = 8 bytes")
	browsers_QUIC_Initial.add("Firefox 116 (B)", &uquic.QUICFirefox_116B, "Destination Connection ID length = 9 bytes")
	browsers_QUIC_Initial.add("Firefox 116 (C)", &uquic.QUICFirefox_116C, "Destination Connection ID length = 15 bytes")
	browsers_QUIC_Initial.add("Chrome 115 (IPv4)", &uquic.QUICChrome_115_IPv4, "")
	browsers_QUIC_Initial.add("Chrome 115 (IPv6)", &uquic.QUICChrome_115_IPv6, "")

	protocols_TLS.add("TLS 1.2", 0, "", "TLS_12")
	protocols_TLS.add("TLS 1.3", 1, "", "TLS_13")
	protocols_TLS.add("TLS 1.3 -> 1.2", 2, "TLS 1.3 with fallback to TLS 1.2", "TLS_12+TLS_13")
}

func main() {
	fmt.Printf("\npayload-generator v%s by Ori & Funsy\n\n----------------------------------------\n\n", version)
	var bTLS_id, bQUIC_id, pTLS_id int = -1, -1, -1

	fmt.Println(":: TLS CLIENT-HELLO")
	bTLS_id, pTLS_id = mimicBrowserTLS()
	fmt.Println(bTLS_id, pTLS_id)
	fmt.Print("\033[H\033[2J\n")

	fmt.Println(":: QUIC INITIAL")
	bQUIC_id = mimicBrowserQUIC()
	fmt.Print("\033[H\033[2J\n")

	fmt.Println(":: SETTINGS")
	if bTLS_id < 0 && bQUIC_id < 0 {
		fmt.Print("\033[H\033[2J")
		check(fmt.Errorf("Nothing to do"))
	}

	cropAt = inputCrop()
	SNI = inputSNI()

	fmt.Print("\033[H\033[2J\n")

	fmt.Print(":: INFO\n")
	fmt.Printf("TLS CLientHello: %t\nQUIC Initial: %t\n", (bTLS_id >= 0), (bQUIC_id >= 0))

	if bTLS_id >= 0 {
		fmt.Printf("Browser for TLS ClientHello: %s\n", browsers_TLS_CH[bTLS_id].name)
	}

	if bQUIC_id >= 0 {
		fmt.Printf("Browser for QUIC Initial: %s\n", browsers_QUIC_Initial[bQUIC_id].name)
	}

	fmt.Printf("Crop at: %d\nSNI: %s\n\n----------------------------------------\n\n", cropAt, SNI)

	if bTLS_id >= 0 {
		fmt.Println(":: TCP CLIENT-HELLO")

		go listenTCP(cropAt, &bTLS_id, pTLS_id)
		<-tcpListenerReady

		go sendRequestTLS(&bTLS_id, pTLS_id)
		<-tcpListenerQuitted

		if bQUIC_id < 0 {
			fmt.Printf("\n----------------------------------------\n\n")
		}
	}

	if bQUIC_id >= 0 {
		if bTLS_id >= 0 {
			fmt.Printf("\n")
		}
		fmt.Println(":: UDP QUIC INITIAL")

		go listenUDP(cropAt, &bQUIC_id)
		<-udpListenerReady

		go sendRequestQUIC(&bQUIC_id)
		<-udpListenerQuitted

		fmt.Printf("\n----------------------------------------\n\n")
	}

	fmt.Println("All done, press [ENTER] to exit...")
	fmt.Scanln()

	os.Exit(0)
}

func mimicBrowserTLS() (int, int) {
	var browserIndex int
	fmt.Println("  0. Do not create TLS ClientHello")
	for n, each := range browsers_TLS_CH {
		if each.additional_info != "" {
			fmt.Printf("  %d. %s (%s)\n", n+1, each.name, each.additional_info)
		} else {
			fmt.Printf("  %d. %s\n", n+1, each.name)
		}
	}
	for {
		fmt.Printf("\n> Which browser to mimic for TLS ClientHello (default %s): ", browsers_TLS_CH[0].name)
		var s string
		fmt.Scanln(&s)
		if s == "" {
			browserIndex = 0
			break
		}
		i, err := strconv.Atoi(s)
		if err != nil || i < 0 || i > len(browsers_TLS_CH) {
			fmt.Printf("   > Incorrect value\n")
		} else {
			browserIndex = i - 1
			break
		}
	}
	if browserIndex != -1 {
		fmt.Printf("\033[H\033[2J\n:: TLS VERSION\n")
		for n, each := range protocols_TLS {
			if each.additional_info != "" {
				fmt.Printf("  %d. %s (%s)\n", n+1, each.name, each.additional_info)
			} else {
				fmt.Printf("  %d. %s\n", n+1, each.name)
			}
		}
		for {
			fmt.Printf("\n> Which TLS version to mimic for TLS ClientHello (default %s): ", protocols_TLS[0].name)
			var s string
			fmt.Scanln(&s)
			if s == "" {
				return browserIndex, 0
			}
			i, err := strconv.Atoi(s)
			if err != nil || i < 0 || i > len(protocols_TLS) {
				fmt.Printf("   > Incorrect value\n")
			} else {
				return browserIndex, i - 1
			}
		}
	}
	return -1, -1
}

func mimicBrowserQUIC() int {
	fmt.Println("  0. Do not create QUIC Initial")
	for n, each := range browsers_QUIC_Initial {
		if each.additional_info != "" {
			fmt.Printf("  %d. %s (%s)\n", n+1, each.name, each.additional_info)
		} else {
			fmt.Printf("  %d. %s\n", n+1, each.name)
		}
	}
	for {
		fmt.Printf("\n> Which browser to mimic for QUIC Initial (default %s): ", browsers_QUIC_Initial[0].name)
		var s string
		fmt.Scanln(&s)
		if s == "" {
			return 0
		}
		i, err := strconv.Atoi(s)
		if err != nil || i < 0 || i > len(browsers_QUIC_Initial) {
			fmt.Printf("   > Incorrect value\n")
		} else {
			return (i - 1)
		}
	}
}

func inputCrop() int {
	for {
		fmt.Print("> At which byte to crop binary (default skip): ")
		var s string
		fmt.Scanln(&s)
		if s == "" {
			return -1
		}
		i, err := strconv.Atoi(s)
		if err != nil || i <= 0 || i >= 65534 {
			fmt.Printf("   > Incorrect value\n")
		} else {
			return i
		}
	}
}

func inputSNI() string {
	var s string
	fmt.Printf("> Specify a SNI for payload (default '%s'): ", defaultSNI)
	fmt.Scanln(&s)
	if s != "" {
		return s
	}
	return defaultSNI
}

func sendRequestTLS(browser_id *int, tls_id int) {
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
	}

	tr.DialTLSContext = func(ctx context.Context, network string, addr string) (net.Conn, error) {

		conn, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}

		var minVers, maxVers uint16
		switch tls_id {
		case 0:
			minVers = utls.VersionTLS12
			maxVers = utls.VersionTLS12
		case 1:
			minVers = utls.VersionTLS13
			maxVers = utls.VersionTLS13
		case 2:
			minVers = utls.VersionTLS12
			maxVers = utls.VersionTLS13
		default:
			minVers = utls.VersionTLS12
			maxVers = utls.VersionTLS13
		}

		uCfg := &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			ServerName:         SNI,
			MinVersion:         minVers,
			MaxVersion:         maxVers,
		}

		browserID := *browsers_TLS_CH[*browser_id].utls_pointer
		spec, err := utls.UTLSIdToSpec(browserID)
		if err != nil {
			return nil, err
		}

		for _, ext := range spec.Extensions {
			if sve, ok := ext.(*utls.SupportedVersionsExtension); ok {
				var newVersions []uint16

				for _, v := range sve.Versions {
					if v&0x0f0f == 0x0a0a {
						newVersions = append(newVersions, v)
						continue
					}

					if tls_id == 0 && v == utls.VersionTLS12 {
						newVersions = append(newVersions, v)
					} else if tls_id == 1 && v == utls.VersionTLS13 {
						newVersions = append(newVersions, v)
					} else if tls_id == 2 && (v == utls.VersionTLS13 || v == utls.VersionTLS12) {
						newVersions = append(newVersions, v)
					}
				}

				hasRealVersion := false
				for _, v := range newVersions {
					if v&0x0f0f != 0x0a0a {
						hasRealVersion = true
						break
					}
				}

				if !hasRealVersion {
					switch tls_id {
					case 0:
						newVersions = append(newVersions, utls.VersionTLS12)
					case 1:
						newVersions = append(newVersions, utls.VersionTLS13)
					case 2:
						newVersions = append(newVersions, utls.VersionTLS13, utls.VersionTLS12)
					}
				}

				sve.Versions = newVersions
			}
		}

		uconn := utls.UClient(conn, uCfg, utls.HelloCustom)
		err = uconn.ApplyPreset(&spec)
		if err != nil {
			return nil, err
		}

		err = uconn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		return uconn, nil
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   1 * time.Second,
	}

	client.Get(fmt.Sprintf("https://localhost:%d", loopbackPort))
	client.CloseIdleConnections()
}

func sendRequestQUIC(browser_id *int) {
	roundTripper := &uhttp3.RoundTripper{
		TLSClientConfig: &utls.Config{
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: true,
			ServerName:         SNI,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		},
		QuicConfig: &uquic.Config{},
	}

	quicSpec, err := uquic.QUICID2Spec(*browsers_QUIC_Initial[*browser_id].uquic_pointer)
	check(err)

	uRoundTripper := uhttp3.GetURoundTripper(
		roundTripper,
		&quicSpec,
		nil,
	)
	defer uRoundTripper.Close()

	h3client := &http.Client{
		Timeout:   1 * time.Second,
		Transport: uRoundTripper,
	}

	h3client.Get(fmt.Sprintf("https://localhost:%d", loopbackPort))
	h3client.CloseIdleConnections()
}

func listenTCP(cropAt int, browser_id *int, protocol_id int) {
	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", loopbackPort))
	check(err)
	defer tcpListener.Close()

	tcpListenerReady <- true

	buf := make([]byte, 65535)

	tcpConn, err := tcpListener.Accept()
	check(err)
	defer tcpConn.Close()

	n, err := tcpConn.Read(buf)
	check(err)

	if cropAt < 0 {
		buf = buf[:n]
	} else {
		buf = buf[:cropAt]
	}

	hexString := hex.EncodeToString(buf)
	fmt.Printf("  Hex for TLS ClientHello: %s\n", hexString)

	saveToBinaryFile(buf, "tls_clienthello", protocols_TLS[protocol_id].filename, browsers_TLS_CH[*browser_id].name)

	tcpListenerQuitted <- true
}

func listenUDP(cropAt int, browser_id *int) {

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: loopbackPort})
	check(err)
	defer udpConn.Close()

	buf := make([]byte, 65535)

	udpListenerReady <- true

	n, _, err := udpConn.ReadFromUDP(buf)
	check(err)

	if cropAt < 0 {
		buf = buf[:n]
	} else {
		buf = buf[:cropAt]
	}

	hexString := hex.EncodeToString(buf)
	fmt.Printf("  Hex for QUIC Initial: %s\n", hexString)

	saveToBinaryFile(buf, "quic_initial", "", browsers_QUIC_Initial[*browser_id].name)

	udpListenerQuitted <- true
}

func saveToBinaryFile(b []byte, marker string, tlsVer string, browser string) {
	t := time.Now().Format("2006.01.02 15-04-05")
	filename := ""

	replacer := strings.NewReplacer(".", "_")
	addressToConnWithReplaces := replacer.Replace(SNI)

	if tlsVer == "" {
		filename = fmt.Sprintf("%s_%s_[%s]_[%s].bin", marker, addressToConnWithReplaces, browser, t)
	} else {
		filename = fmt.Sprintf("%s_%s_[%s]_[%s]_[%s].bin", marker, addressToConnWithReplaces, tlsVer, browser, t)
	}

	err := os.WriteFile(filename, b, 0200)
	check(err)

	fmt.Printf("> Saved %d bytes as %s\n", len(b), filename)
}

func check(err error) {
	switch err {
	case nil:
		return
	default:
		fmt.Printf(":: ERROR\n%s", err)
		fmt.Scanln()
		os.Exit(1)
	}
}
