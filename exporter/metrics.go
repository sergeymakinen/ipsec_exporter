package exporter

type metrics struct {
	Stats  stats
	Pools  []pool
	IKESAs []*ikeSA
}

type stats struct {
	Uptime    uptime  `vici:"uptime"`
	Workers   workers `vici:"workers"`
	Queues    queues  `vici:"queues"`
	Scheduled uint64  `vici:"scheduled"`
	IKESAs    ikeSAs  `vici:"ikesas"`
}

type uptime struct {
	Since string `vici:"since"`
}

type workers struct {
	Total  uint64 `vici:"total"`
	Idle   uint64 `vici:"idle"`
	Active queues `vici:"active"`
}

type queues struct {
	Critical uint64 `vici:"critical"`
	High     uint64 `vici:"high"`
	Medium   uint64 `vici:"medium"`
	Low      uint64 `vici:"low"`
}

func (q queues) Total() uint64 { return q.Critical + q.High + q.Medium + q.Low }

type ikeSAs struct {
	Total    uint64 `vici:"total"`
	HalfOpen uint64 `vici:"half-open"`
}

type pool struct {
	Name    string
	Address string `vici:"base"`
	Size    uint64 `vici:"size"`
	Online  uint64 `vici:"online"`
	Offline uint64 `vici:"offline"`
}

type ikeSA struct {
	Name          string
	UID           uint32              `vici:"uniqueid"`
	Version       uint8               `vici:"version"`
	State         string              `vici:"state"`
	LocalHost     string              `vici:"local-host"`
	LocalID       string              `vici:"local-id"`
	RemoteHost    string              `vici:"remote-host"`
	RemoteID      string              `vici:"remote-id"`
	RemoteXAuthID string              `vici:"remote-xauth-id"`
	RemoteEAPID   string              `vici:"remote-eap-id"`
	Established   *int64              `vici:"established"`
	LocalVIPs     []string            `vici:"local-vips"`
	RemoteVIPs    []string            `vici:"remote-vips"`
	ChildSAs      map[string]*childSA `vici:"child-sas"`
}

type childSA struct {
	Name       string   `vici:"name"`
	UID        uint32   `vici:"uniqueid"`
	ReqID      uint32   `vici:"reqid"`
	State      string   `vici:"state"`
	Mode       string   `vici:"mode"`
	Protocol   string   `vici:"protocol"`
	InBytes    uint64   `vici:"bytes-in"`
	InPackets  uint64   `vici:"packets-in"`
	OutBytes   uint64   `vici:"bytes-out"`
	OutPackets uint64   `vici:"packets-out"`
	Installed  *int64   `vici:"install-time"`
	LocalTS    []string `vici:"local-ts"`
	RemoteTS   []string `vici:"remote-ts"`
}
