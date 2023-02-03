package risk

import (
	"net"
	"strconv"
	"strings"
)

func decomposition(v interface{}) (ip string, port int) {
	switch addr := v.(type) {
	case string:
		ip = addr
		port = 0

		s := strings.Split(addr, ":")
		if len(s) == 2 {
			ip = s[0]
			if p, err := strconv.Atoi(s[1]); err == nil {
				port = p
			}
		}

		if port < 1 || port > 65535 {
			return "", 0
		}

		return

	case net.IPNet:
		ip = addr.IP.String()

	case net.IPAddr:
		ip = addr.IP.String()

	case net.Conn:
		switch nt := addr.RemoteAddr().(type) {
		case *net.UDPAddr:
			ip = nt.IP.String()
			port = nt.Port

		case *net.TCPAddr:
			ip = nt.IP.String()
			port = nt.Port
		}

		return

	case net.Addr:
		switch nt := addr.(type) {
		case *net.UDPAddr:
			ip = nt.IP.String()
			port = nt.Port

		case *net.TCPAddr:
			ip = nt.IP.String()
			port = nt.Port
		}
		return
	}

	return
}
