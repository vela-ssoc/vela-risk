package risk

import (
	"testing"
	"time"
)

func TestCodec(t *testing.T) {
	ev := &Event{
		LocalIP:    "192.168.1.1",
		LocalPort:  8080,
		RemoteIP:   "172.31.61.118",
		RemotePort: 3376,
		Payload:    "hello",
		Class:      TBrute,
		Reference:  "http://www.baidu.com",
		Time:       time.Now(),
		Subject:    "testcodec",
	}

	c1 := GenCodec{"local_ip", "remote_ip", "remote_port"}
	v1 := c1.encode(ev)
	t.Log(v1)
}
