package risk

func Brute(ov ...func(*Event)) *Event {
	ev := NewEv(ov...)
	ev.Class = TBrute
	ev.Alert = true
	return ev
}

func HoneyPot(ov ...func(*Event)) *Event {
	ev := NewEv(ov...)
	ev.Class = THoneyPot
	ev.Alert = true
	ev.Level = HIGH
	return ev
}

func WeakPass(ov ...func(*Event)) *Event {
	ev := NewEv(ov...)
	ev.Class = TWeakPass
	ev.Alert = true
	return ev
}

func Crawler(ov ...func(*Event)) *Event {
	ev := NewEv(ov...)
	ev.Class = TCrawler
	ev.Alert = true
	return ev
}

func Virus(ov ...func(*Event)) *Event {
	ev := NewEv(ov...)
	ev.Class = TVirus
	ev.Alert = true
	return ev
}

func Web(ov ...func(*Event)) *Event {
	ev := NewEv(ov...)
	ev.Class = TWeb
	ev.Alert = true
	return ev
}

func Monitor(ov ...func(*Event)) *Event {
	ev := NewEv(ov...)
	ev.Class = TMonitor
	ev.Alert = false
	return ev
}
