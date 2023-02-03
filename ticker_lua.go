package risk

import (
	"fmt"
	"github.com/valyala/fasttemplate"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	"strings"
)

func (tk *ticker) bucketL(L *lua.LState) int {
	bPath := []string{"risk"}
	n := L.GetTop()
	if n == 0 {
		L.RaiseError("%s db got nil", tk.Name())
		return 0
	}

	for i := 1; i <= n; i++ {
		bPath = append(bPath, L.CheckString(i))
	}

	if len(bPath) == 0 {
		L.RaiseError("%s db got empty", tk.Name())
		return 0
	}
	tk.hub = NewBucketHub(bPath, tk.newCookie, tk.onHandle)
	return 0
}

func (tk *ticker) byL(L *lua.LState) int {
	idc := L.IsString(1)
	if idc == "" {
		return 0
	}
	tk.cfg.idc = idc
	tk.cdc = strings.Split(idc, ",")
	return 0
}

func (tk *ticker) hookL(L *lua.LState) int {
	tk.cfg.hook = pipe.NewByLua(L, pipe.Env(xEnv))
	return 0
}

func (tk *ticker) eventL(L *lua.LState) int {
	if !tk.IsRun() {
		L.RaiseError("ticker not running")
		return 0
	}

	obj := L.CheckObject(1)
	ev, ok := obj.(*Event)
	if !ok {
		L.RaiseError("event type error")
		return 0
	}

	tk.cfg.pipe.Do(ev, tk.cfg.co, func(err error) {
		xEnv.Errorf("risk ticker pipe call fail %v", err)
	})

	id := tk.cdc.encode(ev)
	if id == "" {
		L.RaiseError("ticker id encode fail")
		return 0
	}

	cookie := tk.hub.Get(id)
	cookie.Incr(1)
	tk.intercept(cookie, ev)
	cookie.saveFn = func() {
		tk.hub.Set(id, cookie)
	}

	L.Push(cookie)
	return 1
}

func (tk *ticker) pushL(L *lua.LState) int {
	n := L.GetTop()
	if n == 0 {
		return 0
	}

	for i := 1; i <= n; i++ {
		obj := L.CheckObject(i)

		ev, ok := obj.(*Event)
		if !ok {
			continue
		}
		tk.add(ev)
	}

	return 0
}

func (tk *ticker) memoryL(L *lua.LState) int {
	return 0
}

func (tk *ticker) startL(L *lua.LState) int {
	xEnv.Start(L, tk).From(L.CodeVM()).Do()
	return 0
}

func (tk *ticker) alertL(v ...interface{}) error {
	n := len(v)
	if n == 0 {
		return fmt.Errorf("not found ticker tx")
	}

	tx, ok := v[0].(*Tx)
	//idx, ok := v[1].(int)
	cnd, ok := v[2].(string)
	if !ok {
		return nil
	}

	//id  := v[1]
	//cnd := v[2]

	tx.alert(cnd)
	return nil
}

func (tk *ticker) dropL(v ...interface{}) error {
	n := len(v)
	if n == 0 {
		return fmt.Errorf("not found ticker tx")
	}
	tx, ok := v[0].(*Tx)
	//idx, ok := v[1].(int)
	cnd, ok := v[2].(string)
	if !ok {
		return nil
	}

	tx.drop(cnd)
	return nil
}

func (tk *ticker) payload(L *lua.LState) int {
	tmpl := L.IsString(1)
	max := L.IsInt(2)
	if max == 0 {
		max = 100
	}

	if len(tmpl) > 8 {
		tk.cfg.payTmpl = fasttemplate.New(tmpl, "${", "}")
		tk.cfg.payMax = max
	}

	return 0
}

func (tk *ticker) levelL(L *lua.LState) int {
	tk.cfg.level = L.IsString(1)
	return 0
}

func (tk *ticker) classL(L *lua.LState) int {
	tk.cfg.class = CheckClass(L, 1)
	return 0
}

func (tk *ticker) subjectL(L *lua.LState) int {
	tmpl := L.IsString(1)
	if len(tmpl) <= 3 {
		return 0
	}

	tk.cfg.subTmpl = fasttemplate.New(tmpl, "${", "}")
	return 0
}

func (tk *ticker) pipeL(L *lua.LState) int {
	tk.cfg.pipe.CheckMany(L)
	return 0
}

func (tk *ticker) referenceL(L *lua.LState) int {
	tmpl := L.IsString(1)
	if len(tmpl) <= 3 {
		return 0
	}

	tk.cfg.refTmpl = fasttemplate.New(tmpl, "${", "}")
	return 0
}

func (tk *ticker) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "db":
		return lua.NewFunction(tk.bucketL)

	case "db_memory":
		return lua.NewFunction(tk.memoryL)
	case "level":
		return lua.NewFunction(tk.levelL)

	case "class":
		return lua.NewFunction(tk.classL)

	case "subject":
		return lua.NewFunction(tk.subjectL)

	case "pay":
		return lua.NewFunction(tk.payload)

	case "case":
		return tk.cfg.vsh.Index(L, "case")

	case "alert":
		return lua.GoFuncErr(tk.alertL)
	case "drop":
		return lua.GoFuncErr(tk.dropL)

	case "by":
		return lua.NewFunction(tk.byL)

	case "hook":
		return lua.NewFunction(tk.hookL)

	case "push":
		return lua.NewFunction(tk.pushL)

	case "event":
		return lua.NewFunction(tk.eventL)

	case "pipe":
		return lua.NewFunction(tk.pipeL)

	case "reference":
		return lua.NewFunction(tk.referenceL)

	case "start":
		return lua.NewFunction(tk.startL)
	}

	return lua.LNil
}
