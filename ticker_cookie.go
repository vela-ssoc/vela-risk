package risk

import (
	"encoding/json"
	"github.com/vela-ssoc/vela-kit/lua"
	"strings"
	"time"
)

const (
	Initial = CookieState(1) << 1 //初始
	Combine = CookieState(1) << 2 //聚合
	Delete  = CookieState(1) << 3 //删除
	Report  = CookieState(1) << 4 //上报
)

type CookieState uint8

type Cookie struct {
	From    string            `json:"from"`
	State   CookieState       `json:"state"`
	Count   int               `json:"count"`
	PaySize int               `json:"p_size"`
	Payload []string          `json:"payload"`
	Trigger map[string]uint8  `json:"trigger"`
	Last    int64             `json:"last"`
	Data    map[string]string `json:"data"`
	save    bool              `json:"-"`
	saveFn  func()            `json:"-"`
}

func NewCookie(from string) *Cookie {
	return &Cookie{
		From:  from,
		State: Initial,
		Last:  time.Now().Unix(),
	}
}

func (c *Cookie) String() string                         { return lua.B2S(c.Byte()) }
func (c *Cookie) Type() lua.LValueType                   { return lua.LTObject }
func (c *Cookie) AssertFloat64() (float64, bool)         { return 0, false }
func (c *Cookie) AssertString() (string, bool)           { return "", false }
func (c *Cookie) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (c *Cookie) Peek() lua.LValue                       { return c }

func (c *Cookie) Byte() []byte {
	chunk, _ := json.Marshal(c)
	return chunk
}

func (c *Cookie) Incr(v int) {
	c.Count = c.Count + v
}

func (c *Cookie) Cover(v string) {
	c.Payload = []string{v}
}

func (c *Cookie) Have(v string) bool {
	n := len(c.Payload)
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		if c.Payload[i] == v {
			return true
		}
	}

	return false
}

func (c *Cookie) Append(v string) {
	if len(v) == 0 {
		return
	}

	if c.Have(v) {
		return
	}

	c.PaySize = c.PaySize + len(v)
	c.Payload = append(c.Payload, v)
}

func (c *Cookie) Table() map[string]string {
	if c.Data == nil {
		c.Data = make(map[string]string)
	}

	return c.Data
}

func (c *Cookie) Set(key string, val string) {
	if c.Data == nil {
		c.Data = make(map[string]string)
	}
	c.Table()[key] = val
}

func (c *Cookie) Get(key string) string {
	return c.Data[key]
}

func (c *Cookie) StateBit(v CookieState) {
	c.State = c.State | v
}

func (c *Cookie) Is(v CookieState) bool {
	return c.State&v == v
}

func (c *Cookie) Save() {
	c.save = true
}

func (c *Cookie) TriggerInfo(v string) uint8 {
	if c.Trigger == nil {
		return 0
	}

	return c.Trigger[v]

}

func (c *Cookie) TriggerHit(v string, i uint8) {
	if len(v) == 0 {
		return
	}

	if c.Trigger == nil {
		c.Trigger = make(map[string]uint8, 5)
	}

	c.Save()
	c.Trigger[v] = i
}

func (c *Cookie) payloadL(L *lua.LState) int {
	c.Append(L.CheckString(1))
	return 0
}

func (c *Cookie) setL(L *lua.LState) int {
	key := L.IsString(1)
	val := L.IsString(2)
	if len(key) == 0 {
		return 0
	}

	c.Set(key, val)
	return 0
}

func (c *Cookie) saveL(L *lua.LState) int {

	if c.saveFn == nil {
		L.RaiseError("not save function")
		return 0
	}

	c.saveFn()
	return 0
}

func (c *Cookie) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "count":
		return lua.LInt(c.Count)
	case "from":
		return lua.S2L(c.From)
	case "payload":
		return lua.S2L(strings.Join(c.Payload, ","))
	case "payload_size":
		return lua.LInt(c.PaySize)
	case "after":
		now := time.Now().Unix()
		after := now - c.Last
		return lua.LInt(after)
	case "pay":
		return lua.NewFunction(c.payloadL)
	case "set":
		return lua.NewFunction(c.setL)
	case "save":
		return lua.NewFunction(c.saveL)
	default:
		return lua.S2L(c.Data[key])
	}
}

func (c *Cookie) Meta(L *lua.LState, key lua.LValue) lua.LValue {
	return lua.S2L(c.Data[key.String()])
}

func (c *Cookie) NewIndex(L *lua.LState, key string, val lua.LValue) {
	c.Set(key, val.String())
}

func (c *Cookie) NewMeta(L *lua.LState, key lua.LValue, val lua.LValue) {
	c.Set(key.String(), val.String())
}
