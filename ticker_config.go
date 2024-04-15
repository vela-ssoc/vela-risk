package risk

import (
	"github.com/valyala/fasttemplate"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	vswitch "github.com/vela-ssoc/vela-switch"
)

type config struct {
	name    string
	idc     string //ev id codec field
	code    string //from code
	level   string
	class   TClass
	subTmpl *fasttemplate.Template
	refTmpl *fasttemplate.Template
	payTmpl *fasttemplate.Template
	payMax  int
	vsh     *vswitch.Switch
	co      *lua.LState
	output  lua.Writer
	ignore  *cond.Ignore
	filter  *cond.Combine
	pipe    *pipe.Chains
	hook    *pipe.Chains
	expire  int64
}

func newTickerConfig(L *lua.LState) *config {
	cfg := &config{
		name:   L.IsString(1),
		code:   L.CodeVM(),
		level:  NOTICE,
		class:  TUnknown,
		co:     xEnv.Clone(L),
		ignore: cond.NewIgnore(),
		filter: cond.NewCombine(),
		vsh:    vswitch.NewL(L),
		pipe:   pipe.New(pipe.Env(xEnv)),
		expire: int64(L.IsInt(2)),
	}

	return cfg
}

func (cfg *config) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		cfg.name = val.String()
	}
}

func (cfg *config) valid() error {
	if e := auxlib.Name(cfg.name); e != nil {
		return e
	}

	return nil
}
