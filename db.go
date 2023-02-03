package risk

import (
	"context"
	"github.com/vela-ssoc/vela-kit/vela"
	"github.com/vela-ssoc/vela-kit/codec"
	"go.etcd.io/bbolt"
	"time"
)

type dbHub struct {
	codec  codec.Mime
	new    func(string) *Cookie
	handle func(string, *Cookie, *Event)
	db     vela.Bucket
}

func (hub *dbHub) Del(id string) {
	hub.db.Delete(id)
}

func (hub *dbHub) Set(id string, cookie *Cookie) {
	if cookie == nil {
		return
	}

	data, err := hub.codec.Marshal(cookie)
	if err != nil {
		return
	}
	hub.db.Push(id, data, 0)
}

func (hub *dbHub) Get(id string) *Cookie {
	chunk, err := hub.db.Value(id)
	if err != nil {
		xEnv.Debugf("%s find id fail %v", id, err)
		return hub.new(id)
	}

	c := &Cookie{}
	err = hub.codec.Unmarshal(chunk, c)
	if err != nil {
		xEnv.Infof("%s cookie decode %s fail %v", id, string(chunk), err)
		hub.db.Delete(id)
		return hub.new(id)
	}

	c.StateBit(Combine)
	return c

}

func (hub *dbHub) call(id string, cookie *Cookie, ev *Event) {
	if hub.handle == nil {
		return
	}
	hub.handle(id, cookie, ev)
}

func (hub *dbHub) DelBatch(v []string) {
	n := len(v)
	if n == 0 {
		return
	}

	hub.db.Batch(func(tx *bbolt.Tx, bbt *bbolt.Bucket) error {
		for _, id := range v {
			bbt.Delete([]byte(id))
		}
		return nil
	}, true)
}

func (hub *dbHub) SetBatch(val []Tx) {
	if len(val) <= 0 {
		return
	}
	db := hub.db
	err := db.Batch(
		func(tx *bbolt.Tx, bbt *bbolt.Bucket) error {
			for _, tv := range val {
				chunk, err := db.Encode(tv.Cookie.Byte(), 0)
				if err != nil {
					continue
				}

				err = bbt.Put([]byte(tv.Id), chunk)
				if err != nil {
					xEnv.Errorf("%s put fail %v", hub.db.Names(), err)
				}
			}
			return nil
		},
		true)

	if err != nil {
		xEnv.Errorf("%v db batch save fail %v", db.Names(), err)
	}
}

func (hub *dbHub) Range(over *bool) {
	var deletes []string
	var cookies []Tx
	hub.db.ForEach(func(id string, chunk []byte) {
		if *over {
			return
		}
		var cookie Cookie
		if err := hub.codec.Unmarshal(chunk, &cookie); err != nil {
			deletes = append(deletes, id)
			return
		}

		hub.call(id, &cookie, nil)
		if cookie.Is(Delete) {
			deletes = append(deletes, id)
		}

		if cookie.save {
			cookies = append(cookies, Tx{Id: id, Cookie: &cookie})
		}
	})

	hub.DelBatch(deletes)
	hub.SetBatch(cookies)
}

func (hub *dbHub) Poll(ctx context.Context, tv int) {
	tk := time.NewTicker(time.Duration(tv) * time.Second)
	defer tk.Stop()

	over := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			hub.Range(&over)
		}
	}
}

func NewBucketHub(
	bkt []string,
	new func(string) *Cookie,
	handle func(string, *Cookie, *Event),
) *dbHub {
	return &dbHub{
		db:     xEnv.Bucket(bkt...),
		new:    new,
		codec:  codec.Sonic{},
		handle: handle,
	}
}
