package risk

import (
	"context"
	"fmt"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/lua"
	"reflect"
	"time"
)

var tickerTypeOf = reflect.TypeOf((*ticker)(nil)).String()

type ticker struct {
	lua.SuperVelaData
	cfg  *config
	ctx  context.Context
	kill context.CancelFunc
	cdc  GenCodec
	hub  *dbHub
}

func newTicker(cfg *config) *ticker {
	tk := &ticker{cfg: cfg}
	tk.V(lua.VTInit, tickerTypeOf, time.Now())
	return tk
}

func (tk *ticker) Name() string {
	return tk.cfg.name
}

func (tk *ticker) Type() string {
	return tickerTypeOf
}

func (tk *ticker) Start() error {
	if e := tk.cfg.valid(); e != nil {
		return e
	}

	if tk.hub == nil {
		return fmt.Errorf("not found cookie hub")
	}

	ctx, kill := context.WithCancel(context.Background())

	go tk.hub.Poll(ctx, 1)

	tk.ctx = ctx
	tk.kill = kill
	return nil
}

func (tk *ticker) Close() error {
	if tk.kill != nil {
		tk.kill()
	}

	return nil
}

func (tk *ticker) newEvent(id string, cookie *Cookie, ev *Event) *Tx {

	tx := &Tx{
		cfg:    tk.cfg,
		Id:     id,
		Cookie: cookie,
		ent:    ev,
	}

	if ev != nil {
		return tx
	}

	key := tk.cdc.Parse(id)
	tx.ent = key.To()
	return tx
}

func (tk *ticker) onHandle(id string, cookie *Cookie, ev *Event) {
	tx := tk.newEvent(id, cookie, ev)
	if len(cookie.Trigger) == 0 {
		tk.cfg.vsh.ByIgnoreAndCallback(tx, nil, cookie.TriggerHit)
		return
	}

	trigger := make([]string, len(cookie.Trigger))
	for cnd, _ := range cookie.Trigger {
		trigger = append(trigger, cnd)
	}

	cnd := cond.New()
	section := cond.NewSection()
	section.Method(cond.Eq)
	section.Keys("*")
	section.Value(trigger...)
	cnd.Append(section)

	tk.cfg.vsh.ByIgnoreAndCallback(tx, cnd, cookie.TriggerHit)
}

func (tk *ticker) intercept(cookie *Cookie, ev *Event) {
	if tk.cfg.payTmpl != nil && cookie.PaySize < tk.cfg.payMax {
		val := tk.cfg.payTmpl.ExecuteFuncString(ev.ExecTmpl)
		cookie.Append(val)
	}

	if tk.cfg.hook == nil {
		return
	}

	tk.cfg.hook.Call2(cookie, ev, tk.cfg.co)
}

func (tk *ticker) newCookie(id string) *Cookie {
	return NewCookie(tk.cfg.code)
}

func (tk *ticker) add(ev *Event) {
	if !tk.IsRun() {
		return
	}

	tk.cfg.pipe.Do(ev, tk.cfg.co, func(err error) {
		xEnv.Errorf("risk ticker pipe call fail %v", err)
	})

	id := tk.cdc.encode(ev)
	if id == "" {
		return
	}

	cookie := tk.hub.Get(id)
	cookie.Incr(1)
	tk.intercept(cookie, ev)
	tk.hub.Set(id, cookie)
}
