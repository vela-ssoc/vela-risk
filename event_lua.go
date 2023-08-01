package risk

import (
	auxlib2 "github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	vtime "github.com/vela-ssoc/vela-time"
)

func (ev *Event) String() string                         { return lua.B2S(ev.Byte()) }
func (ev *Event) Type() lua.LValueType                   { return lua.LTObject }
func (ev *Event) AssertFloat64() (float64, bool)         { return 0, false }
func (ev *Event) AssertString() (string, bool)           { return "", false }
func (ev *Event) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ev *Event) Peek() lua.LValue                       { return ev }

func (ev *Event) payloadL(L *lua.LState) int {
	ev.Payload = auxlib2.Format(L, 0)
	return 0
}

func (ev *Event) subjectL(L *lua.LState) int {
	ev.Subject = auxlib2.Format(L, 0)
	return 0
}

func (ev *Event) referenceL(L *lua.LState) int {
	ev.Reference = auxlib2.Format(L, 0)
	return 0
}

func (ev *Event) logL(L *lua.LState) int {
	ev.Log()
	return 0
}

func (ev *Event) sendL(L *lua.LState) int {
	ev.Send()
	return 0
}

func (ev *Event) toL(L *lua.LState) int {
	pip := pipe.NewByLua(L)
	pip.Do(ev, L, func(err error) {
		xEnv.Errorf("%s to pipe call fail %v", ev.String(), err)
	})
	return 0
}

func (ev *Event) metadataL(L *lua.LState) int {
	key := L.CheckString(1)
	val := L.Get(2)

	if val.Type() == lua.LTNil {
		return 0
	}

	if ev.Metadata == nil {
		ev.Metadata = make(map[string]lua.LValue, 8)
	}
	ev.Metadata[key] = val
	return 0
}

func (ev *Event) alertL(L *lua.LState) int {
	ev.Alert = L.IsTrue(1)
	L.Push(ev)
	return 1
}

// ev.P("alert:true","class:123456" , "payload:123123123").send()
func (ev *Event) paramL(L *lua.LState) int {
	L.Callback(func(lv lua.LValue) bool {
		if lv.Type() != lua.LTString {
			return true
		}
		key, val := auxlib2.ParamLValue(lv.String())
		ev.NewIndex(L, key, val)
		return false
	})

	L.Push(ev)
	return 1
}

func (ev *Event) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "minion_id":
		return lua.S2L(ev.MinionId)
	case "inet":
		return lua.S2L(ev.Inet)
	case "class":
		return lua.S2L(ev.Class.String())
	case "level":
		return lua.S2L(ev.Level)
	case "from":
		return lua.S2L(ev.FromCode)
	case "payload":
		return lua.S2L(ev.Payload)
	case "subject":
		return lua.S2L(ev.Subject)
	case "local_ip":
		return lua.S2L(ev.LocalIP)
	case "local_port":
		return lua.LInt(ev.LocalPort)
	case "remote_ip":
		return lua.S2L(ev.RemoteIP)
	case "remote_port":
		return lua.LInt(ev.RemotePort)
	case "region":
		return lua.S2L(ev.Region)
	case "time":
		return vtime.New(ev.Time)
	case "reference":
		return lua.S2L(ev.Reference)
	case "alert":
		return lua.LBool(ev.Alert)

	case "payloadf":
		return lua.NewFunction(ev.payloadL)
	case "subjectf":
		return lua.NewFunction(ev.subjectL)
	case "referencef":
		return lua.NewFunction(ev.referenceL)

	case "p":
		return lua.NewFunction(ev.paramL)

	case "log":
		return lua.NewFunction(ev.logL)
	case "send":
		return lua.NewFunction(ev.sendL)
	case "to":
		return lua.NewFunction(ev.toL)
	case "metadata":
		return lua.NewFunction(ev.metadataL)

	default:
		if v, ok := ev.Metadata[key]; ok {
			return v
		}
		return lua.LNil
	}

}

func (ev *Event) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "minion_id":
		ev.MinionId = val.String()
	case "inet":
		ev.Inet = val.String()

	case "class":
		ev.Class = TClass(lua.IsInt(val))
	case "level":
		ev.Leve(val.String())
	case "from":
		ev.FromCode = val.String()

	case "payload":
		ev.Payload = val.String()

	case "subject":
		ev.Subject = val.String()
	case "local_ip":
		ev.LocalIP = val.String()
	case "local_port":
		ev.LocalPort = lua.IsInt(val)

	case "remote_ip":
		ev.RemoteIP = val.String()
		ev.SearchRegion()

	case "remote_port":
		ev.RemotePort = lua.IsInt(val)
	case "reference", "ref":
		ev.Reference = val.String()
	case "alert":
		ev.Alert = lua.IsTrue(val)
	case "template":
		ev.Template = val.String()
	}

}

func newEvL(L *lua.LState) *Event {
	ev := newEv()
	lv := L.Get(1)
	switch lv.Type() {
	case lua.LTString:
		ev.Subject = lv.String()
	case lua.LTTable:
		lv.(*lua.LTable).Range(func(key string, val lua.LValue) {
			ev.NewIndex(L, key, val)
		})
	}
	return ev
}
