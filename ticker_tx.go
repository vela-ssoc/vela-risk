package risk

import (
	"encoding/json"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"io"
	"strconv"
	"strings"
	"time"
)

type Tx struct {
	cfg    *config `json:"-"`
	ent    *Event  `json:"-'"` //key event demo
	Id     string  `json:"id"`
	Cookie *Cookie `json:"cookie"`
}

func (tx *Tx) String() string                         { return lua.B2S(tx.Byte()) }
func (tx *Tx) Type() lua.LValueType                   { return lua.LTObject }
func (tx *Tx) AssertFloat64() (float64, bool)         { return 0, false }
func (tx *Tx) AssertString() (string, bool)           { return "", false }
func (tx *Tx) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (tx *Tx) Peek() lua.LValue                       { return tx }

func (tx *Tx) Byte() []byte {
	chunk, _ := json.Marshal(tx)
	return chunk
}

func (tx *Tx) LocalIP() string {
	if tx.ent.LocalIP != "" {
		return tx.ent.LocalIP
	}
	return tx.Cookie.Data["local_ip"]
}

func (tx *Tx) LocalPort() int {
	if tx.ent.LocalPort != -1 {
		return tx.ent.LocalPort
	}

	v := tx.Cookie.Data["local_port"]
	n, _ := strconv.Atoi(v)
	return n
}

func (tx *Tx) RemoteIP() string {
	if tx.ent.RemoteIP != "" {
		return tx.ent.RemoteIP
	}
	return tx.Cookie.Data["remote_ip"]
}

func (tx *Tx) RemotePort() int {
	if tx.ent.RemotePort != -1 {
		return tx.ent.RemotePort
	}

	v := tx.Cookie.Data["remote_port"]
	n, _ := strconv.Atoi(v)
	return n
}

func (tx *Tx) Reference() string {
	return tx.cfg.refTmpl.ExecuteFuncString(func(w io.Writer, tag string) (int, error) {
		return w.Write(auxlib.S2B(tx.Index(nil, tag).String()))
	})
}

func (tx *Tx) Class() TClass {
	return tx.cfg.class
}

func (tx *Tx) Level() string {
	return tx.cfg.level
}

func (tx *Tx) Subject() string {
	if tx.cfg.subTmpl == nil {
		return "事件未定义"
	}
	return tx.cfg.subTmpl.ExecuteFuncString(func(w io.Writer, tag string) (int, error) {
		return w.Write(auxlib.S2B(tx.Index(nil, tag).String()))
	})
}

func (tx *Tx) alert(cnd string) {
	if tx.Cookie.TriggerInfo(cnd) != 0 {
		return
	}

	ev := &Event{
		MinionId:   xEnv.ID(),
		Inet:       xEnv.Inet(),
		Time:       time.Now(),
		Level:      tx.Level(),
		Class:      tx.Class(),
		LocalIP:    tx.LocalIP(),
		LocalPort:  tx.LocalPort(),
		RemoteIP:   tx.RemoteIP(),
		RemotePort: tx.RemotePort(),
		Payload:    strings.Join(tx.Cookie.Payload, "\n"),
		FromCode:   tx.Cookie.From,
		Alert:      true,
		Subject:    tx.Subject(),
	}

	ev.SearchRegion()
	ev.Send()
	tx.Cookie.TriggerHit(cnd, 1)
}

func (tx *Tx) drop(cnd string) {
	tx.Cookie.StateBit(Delete)
}

func (tx *Tx) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "id":
		return lua.S2L(tx.Id)
	case "cookie":
		return tx.Cookie

	case "node":
		return lua.S2L(xEnv.Inet())
	case "after":
		after := time.Now().Unix() - tx.Cookie.Last
		return lua.LInt(after)
	case "count":
		return lua.LInt(tx.Cookie.Count)
	case "local_ip":
		return lua.S2L(tx.LocalIP())
	case "remote_ip":
		return lua.S2L(tx.RemoteIP())
	case "local_port":
		return lua.LInt(tx.LocalPort())
	case "remote_port":
		return lua.LInt(tx.RemotePort())
	}

	if strings.HasPrefix(key, "ev_") && len(key) >= 5 {
		return tx.ent.Index(L, key[3:])
	}

	if strings.HasPrefix(key, "cookie_") {
		return tx.Cookie.Index(L, key[7:])
	}

	return lua.LNil
}
