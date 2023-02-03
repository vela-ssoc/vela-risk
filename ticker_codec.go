package risk

import (
	"bytes"
	"fmt"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"strings"
)

const (
	Separator    = byte(0x1C)
	SeparatorStr = string(byte(0x1C))
)

type GenCodec []string

func (c GenCodec) Len() int {
	return len(c)
}

func (c GenCodec) Parse(raw string) GenKey {
	key := GenKey{}
	val := strings.Split(raw, SeparatorStr)
	vn := len(val)
	cn := c.Len()
	if cn != vn {
		key.err = fmt.Errorf("codec alignment failed codec.len=%d val.len=%d", cn, vn)
		return key
	}
	key.val = val
	key.cdc = c

	return key
}

func (c GenCodec) encode(ev *Event) string {
	n := len(c)
	if n == 0 {
		return ""
	}

	var buf bytes.Buffer
	for i, item := range c {
		if i > 0 {
			buf.WriteByte(Separator)
		}

		if v := ev.Index(nil, item); v.Type() != lua.LTNil {
			buf.WriteString(v.String())
		} else {
			buf.WriteString(item)
		}
	}
	return buf.String()
}

func (c GenCodec) decode(val []string) *Event {
	n := len(c)
	if len(val) != n {
		return nil
	}

	ev := &Event{LocalPort: -1, RemotePort: -1}
	for i, item := range c {
		var lv lua.LValue

		switch item {
		case "local_port", "remote_port":
			lv = lua.LInt(auxlib.ToInt(val[i]))
			ev.NewIndex(nil, item, lv)

		default:
			ev.NewIndex(nil, item, lua.S2L(val[i]))
		}
	}

	return ev
}

func (c GenCodec) Field(val string, name string) string {
	n := len(c)
	if n == 0 {
		return ""
	}

	vs := strings.Split(val, SeparatorStr)
	if len(vs) != n {
		return ""
	}

	for i, item := range c {
		if name == item {
			return vs[i]
		}
	}
	return ""
}

func (c GenCodec) Have(name string) int {
	n := len(c)
	if n == 0 {
		return -1
	}
	for i, item := range c {
		if name == item {
			return i
		}
	}
	return -1
}

type GenKey struct {
	val []string
	cdc GenCodec
	err error
}

func (k GenKey) Ok() bool {
	return k.err == nil
}

func (k GenKey) Have(name string) bool {
	return k.cdc.Have(name) != -1
}

func (k GenKey) To() *Event {
	if !k.Ok() {
		return nil
	}
	return k.cdc.decode(k.val)
}
