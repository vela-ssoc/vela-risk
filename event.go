package risk

import (
	"encoding/json"
	"fmt"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/kind"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/strutil"
	"io"
	"regexp"
	"time"
)

var format = fmt.Sprintf

var (
	emc   = regexp.MustCompile("[0-9a-z]{3,8}")
	mail  = regexp.MustCompile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
	phone = regexp.MustCompile("^1[3-9][0-9]{9}$")
)

type Ding struct {
	Type string `json:"type"`
	User string `json:"user"`
	Mask string `json:"mask"`
}

func (d *Ding) Check() error {
	switch d.Type {
	case "emc":
		if !emc.Match(strutil.S2B(d.User)) {
			return fmt.Errorf("invalid emc %s", d.User)
		}
	case "mail":
		if !mail.Match(strutil.S2B(d.User)) {
			return fmt.Errorf("invalid mail %s", d.User)
		}
	case "sms":
		if !mail.Match(strutil.S2B(d.User)) {
			return fmt.Errorf("invalid phone %s", d.User)
		}
	case "phone":
		if !phone.Match(strutil.S2B(d.User)) {
			return fmt.Errorf("invalid phone %s", d.User)
		}

	default:
		return fmt.Errorf("ding type %s", d.Type)
	}

	return nil
}

type Event struct {
	MinionId   string                `json:"minion_id"`
	Inet       string                `json:"inet"`
	Class      TClass                `json:"class"`
	Level      string                `json:"level"`
	Payload    string                `json:"payload"`
	Subject    string                `json:"subject"`
	LocalIP    string                `json:"local_ip"`
	LocalPort  int                   `json:"local_port"`
	RemoteIP   string                `json:"remote_ip"`
	RemotePort int                   `json:"remote_port"`
	Region     string                `json:"region"`
	Time       time.Time             `json:"time"`
	Reference  string                `json:"reference"`
	FromCode   string                `json:"from_code"`
	Alert      bool                  `json:"alert"`
	Template   string                `json:"template"`
	Metadata   map[string]lua.LValue `json:"metadata"`
	Ding       []Ding                `json:"ding"`
}

func newEv() *Event {
	return &Event{
		MinionId: xEnv.ID(),
		Inet:     xEnv.Inet(),
		LocalIP:  xEnv.Inet(),
		Time:     time.Now(),
		Level:    NOTICE,
		Alert:    false,

		Payload:  "-",
		Subject:  "-",
		RemoteIP: "-",
		FromCode: "-",
	}
}

func NewEv(ov ...func(*Event)) *Event {
	ev := newEv()
	for _, fn := range ov {
		fn(ev)
	}
	return ev
}

func (ev *Event) SearchRegion() {
	info, err := xEnv.Region(ev.RemoteIP)
	if err != nil {
		xEnv.Infof("%s not found region info fail %v", ev.RemoteIP, err)
		return
	}

	ev.Region = auxlib.B2S(info.Byte())
	return
}

func (ev *Event) Subjectf(f string, v ...interface{}) {
	ev.Subject = format(f, v...)
}

func (ev *Event) Payloadf(f string, v ...interface{}) {
	ev.Payload = format(f, v...)
}

func (ev *Event) Local(v interface{}) {
	ip, port := decomposition(v)
	if ip == "" {
		return
	}

	ev.LocalIP = ip
	ev.LocalPort = port
}

func (ev *Event) Remote(v interface{}) {
	ip, port := decomposition(v)
	if ip == "" {
		return
	}

	ev.RemoteIP = ip
	ev.RemotePort = port
	ev.SearchRegion()
}

func (ev *Event) From(v interface{}) {
	switch c := v.(type) {
	case string:
		ev.FromCode = c
	case *lua.LState:
		ev.FromCode = c.CodeVM()
	case *lua.VelaData:
		ev.FromCode = c.CodeVM()
	}
}

func (ev *Event) High() {
	ev.Level = HIGH
}
func (ev *Event) Serious() {
	ev.Level = SERIOUS
}

func (ev *Event) Middle() {
	ev.Level = MIDDLE
}

func (ev *Event) Notice() {
	ev.Level = NOTICE
}

func (ev *Event) Leve(v string) {
	switch v {
	case SERIOUS, HIGH, MIDDLE, NOTICE:
		ev.Level = v
	default:
		ev.Level = NOTICE
	}
}

func (ev *Event) Set(key string, lv lua.LValue) {
	if ev.Metadata == nil {
		ev.Metadata = make(map[string]lua.LValue, 8)
	}
	ev.Metadata[key] = lv
}

func (ev *Event) Mt() []byte {
	if ev.Metadata == nil {
		return nil
	}

	mt := kind.NewJsonEncoder()

	mt.Tab("")
	for key, val := range ev.Metadata {
		mt.KV(key, val)
	}
	mt.End("}")

	return mt.Bytes()
}

func (ev *Event) DingMarshal(enc *kind.JsonEncoder) {
	enc.Arr("ding")
	for _, d := range ev.Ding {
		enc.KV("type", d.Type)
		enc.KV("user", d.User)
		enc.KV("mask", d.Mask)
	}
	enc.End("],")
}

func (ev *Event) SetDing(d Ding) {
	n := len(ev.Ding)
	for i := 0; i < n; i++ {
		if ev.Ding[i].Type == d.Type && ev.Ding[i].User == d.User {
			return
		}
	}

	ev.Ding = append(ev.Ding, d)
}

func (ev *Event) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("minion_id", ev.MinionId)
	enc.KV("inet", ev.Inet)
	enc.KV("class", ev.Class.String())
	enc.KV("level", ev.Level)
	enc.KV("payload", ev.Payload)
	enc.KV("subject", ev.Subject)
	enc.KV("local_ip", ev.LocalIP)
	enc.KV("local_port", ev.LocalPort)
	enc.KV("remote_ip", ev.RemoteIP)
	enc.KV("remote_port", ev.RemotePort)
	enc.KV("region", ev.Region)
	enc.KV("time", ev.Time)
	enc.KV("reference", ev.Reference)
	enc.KV("time", ev.Time)
	enc.KV("from_code", ev.FromCode)
	enc.KV("alert", ev.Alert)
	enc.KV("template", ev.Template)
	enc.Raw("metadata", ev.Mt())
	ev.DingMarshal(enc)
	enc.End("}")
	return enc.Bytes()
}

func (ev *Event) Send() {
	err := xEnv.Push("/api/v1/broker/audit/risk", json.RawMessage(ev.Byte()))
	if err != nil {
		xEnv.Errorf("risk event %v send fail %v", ev, err)
	}
}

func (ev *Event) ExecTmpl(w io.Writer, key string) (int, error) {
	chunk := auxlib.S2B(ev.Index(nil, key).String())
	return w.Write(chunk)
}

func (ev *Event) Log() {
	xEnv.Errorf("%v", ev)
}
