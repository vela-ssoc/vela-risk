package risk

import "github.com/vela-ssoc/vela-kit/lua"

func (tk *ticker) newRickEv(t TClass, level string) lua.LValue {
	return lua.NewFunction(func(co *lua.LState) int {
		ev := newEvL(co)
		ev.Class = t
		ev.Leve(level)
		ev.FromCode = co.CodeVM()
		co.Push(ev)
		return 1
	})
}
