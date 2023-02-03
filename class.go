package risk

import "github.com/vela-ssoc/vela-kit/lua"

const (
	TBrute TClass = iota + 1
	TVirus
	TWeakPass
	TCrawler
	THoneyPot
	TWeb
	TLogin
	TMonitor
	TUnknown
)

var classTab = []string{"暴力破解", "病毒事件", "弱口令", "数据爬虫", "蜜罐应用", "web攻击", "登录事件", "监控事件", "未知事件"}

const (
	SERIOUS string = "紧急"
	HIGH    string = "高危"
	MIDDLE  string = "中危"
	NOTICE  string = "低危"
)

type TClass int

func (tc TClass) String() string {
	if tc < 1 || tc > TUnknown {
		return ""
	}

	return classTab[tc-1]
}

func (tc TClass) Type() lua.LValueType                   { return lua.LTObject }
func (tc TClass) AssertFloat64() (float64, bool)         { return 0, false }
func (tc TClass) AssertString() (string, bool)           { return "", false }
func (tc TClass) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (tc TClass) Peek() lua.LValue                       { return tc }

func CheckClass(L *lua.LState, idx int) TClass {
	object := L.CheckObject(idx)

	tv, ok := object.(TClass)
	if ok {
		return tv
	}

	L.RaiseError("invalid risk class , got %p", object)
	return TUnknown
}

func WithClass(v string) TClass {
	switch v {
	case "brute":
		return TBrute
	case "virus":
		return TVirus
	case "weak":
		return TWeakPass
	case "web":
		return TWeb
	case "crawler":
		return TCrawler
	case "honey_pot":
		return THoneyPot
	case "login":
		return TLogin
	case "monitor":
		return TMonitor

	default:
		return TUnknown
	}

}
