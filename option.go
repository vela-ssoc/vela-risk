package risk

func Name(v string) func(*Event) {
	return func(ev *Event) {
		switch v {
		case "暴力破解":
			ev.Class = TBrute
		case "病毒事件":
			ev.Class = TVirus
		case "弱口令":
			ev.Class = TWeakPass
		case "数据爬虫":
			ev.Class = TCrawler
		case "蜜罐应用":
			ev.Class = THoneyPot
		case "web攻击":
			ev.Class = TWeb
		case "登录事件":
			ev.Class = TLogin
		case "监控事件":
			ev.Class = TMonitor

		case "未知事件":
			ev.Class = TUnknown
		default:
			ev.Class = TUnknown
		}
	}
}

func Class(v TClass) func(*Event) {
	return func(ev *Event) {
		ev.Class = v
	}
}

func Subject(f string, v ...interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Subjectf(f, v...)
	}
}

func Remote(v interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Remote(v)
	}
}

func RPort(v int) func(*Event) {
	return func(ev *Event) {
		ev.RemotePort = v
	}
}

func Local(v interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Local(v)
	}
}

func LPort(v int) func(*Event) {
	return func(ev *Event) {
		ev.LocalPort = v
	}
}

func Payload(f string, v ...interface{}) func(*Event) {
	return func(ev *Event) {
		ev.Payloadf(f, v...)
	}
}

func Refer(v string) func(*Event) {
	return func(ev *Event) {
		ev.Reference = v
	}
}

func Leve(v string) func(*Event) {
	return func(ev *Event) {
		ev.Leve(v)
	}
}

func From(v interface{}) func(*Event) {
	return func(ev *Event) {
		ev.From(v)
	}
}

func Alert(v bool) func(*Event) {
	return func(ev *Event) {
		ev.Alert = v
	}
}
