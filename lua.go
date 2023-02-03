package risk

import (
	"github.com/vela-ssoc/vela-kit/vela"
	"github.com/vela-ssoc/vela-kit/lua"
)

var xEnv vela.Environment

func newLuaRiskFunc(v TClass, level string) lua.LValue {
	return lua.NewFunction(func(L *lua.LState) int {
		ev := newEvL(L)
		ev.Class = v
		ev.Leve(level)
		ev.FromCode = L.CodeVM()
		L.Push(ev)
		return 1
	})
}

func newLuaRiskEv(L *lua.LState) int {
	L.Push(newEvL(L))
	return 1
}

func newLuaRiskTickerL(L *lua.LState) int {
	cfg := newTickerConfig(L)
	poc := L.NewVelaData(cfg.name, tickerTypeOf)
	if poc.IsNil() {
		poc.Set(newTicker(cfg))
	} else {
		old := poc.Data.(*ticker)
		old.cfg = cfg
	}
	L.Push(poc)
	return 1
}

func WithEnv(env vela.Environment) {
	xEnv = env
	tab := lua.NewUserKV()
	tab.Set("TBrute", TBrute)
	tab.Set("TVirus", TVirus)
	tab.Set("TWeakPass", TWeakPass)
	tab.Set("TCrawler", TCrawler)
	tab.Set("THoneyPot", THoneyPot)
	tab.Set("TWeb", TWeb)
	tab.Set("TLogin", TLogin)
	tab.Set("TMonitor", TMonitor)
	tab.Set("brute", newLuaRiskFunc(TBrute, HIGH))
	tab.Set("virus", newLuaRiskFunc(TVirus, SERIOUS))
	tab.Set("weak_pass", newLuaRiskFunc(TWeakPass, HIGH))
	tab.Set("crawler", newLuaRiskFunc(TCrawler, MIDDLE))
	tab.Set("web", newLuaRiskFunc(TWeb, HIGH))
	tab.Set("login", newLuaRiskFunc(TLogin, HIGH))
	tab.Set("honey_pot", newLuaRiskFunc(THoneyPot, HIGH))
	tab.Set("monitor", newLuaRiskFunc(TMonitor, NOTICE))
	tab.Set("ticker", lua.NewFunction(newLuaRiskTickerL))

	xEnv.Set("risk", lua.NewExport("vela.risk.export",
		lua.WithTable(tab), lua.WithFunc(newLuaRiskEv)))
}
