package metric

type Metrics struct {
	Stats  Stats
	Pools  []Pool
	IKESAs []*IkeSA
}

type Stats struct {
	Uptime    Uptime   `vici:"uptime"`
	Workers   *Workers `vici:"workers"`
	Queues    *Queues  `vici:"queues"`
	Scheduled *uint64  `vici:"scheduled"`
	IKESAs    IkeSAs   `vici:"ikesas"`
}

type Uptime struct {
	Since string `vici:"since"`
}

type Workers struct {
	Total  uint64 `vici:"total"`
	Idle   uint64 `vici:"idle"`
	Active Queues `vici:"active"`
}

type Queues struct {
	Critical uint64 `vici:"critical"`
	High     uint64 `vici:"high"`
	Medium   uint64 `vici:"medium"`
	Low      uint64 `vici:"low"`
}

func (q Queues) Total() uint64 { return q.Critical + q.High + q.Medium + q.Low }

type IkeSAs struct {
	Total    uint64 `vici:"total"`
	HalfOpen uint64 `vici:"half-open"`
}

type Pool struct {
	Name    string
	Address string `vici:"base"`
	Size    uint64 `vici:"size"`
	Online  uint64 `vici:"online"`
	Offline uint64 `vici:"offline"`
}

type IkeSA struct {
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
	ChildSAs      map[string]*ChildSA `vici:"child-sas"`
}

type ChildSA struct {
	Name       string   `vici:"name"`
	UID        uint32   `vici:"uniqueid"`
	ReqID      *uint32  `vici:"reqid"`
	State      string   `vici:"state"`
	Mode       string   `vici:"mode"`
	Protocol   string   `vici:"protocol"`
	InBytes    uint64   `vici:"bytes-in"`
	InPackets  *uint64  `vici:"packets-in"`
	OutBytes   uint64   `vici:"bytes-out"`
	OutPackets *uint64  `vici:"packets-out"`
	Installed  *int64   `vici:"install-time"`
	LocalTS    []string `vici:"local-ts"`
	RemoteTS   []string `vici:"remote-ts"`
}
