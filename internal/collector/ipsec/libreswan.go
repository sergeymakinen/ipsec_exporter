package ipsecmetrics

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/spheromak/ipsec_exporter/pkg/metric"
)

const (
	lsPrefix     = `^[^ ]+ `
	lsIPAddrPart = `[a-f0-9:.]+`
	lsIPNetPart  = lsIPAddrPart + `/\d+`
	lsConnPart   = `"(?P<conname>[^"]+)"(?P<coninst>\[\d+])?`
	lsConn       = `(?P<prefix>` +
		lsPrefix +
		lsConnPart +
		`)` +
		`:[ ]+`
	lsAddr = `(?P<leftclient>` + lsIPNetPart + `===)?` +
		`(?P<leftaddr>` + lsIPAddrPart + `)` +
		`(?P<lefthost><[^>]+?>)?` +
		`(?P<leftid>\[[^\]]+?])?` +
		`(?P<lefthop>---` + lsIPAddrPart + `)?` +
		`\.\.\.` +
		`(?P<righthop>` + lsIPAddrPart + `---)?` +
		`(?P<rightaddr>` + lsIPAddrPart + `|%any)` +
		`(?P<righthost><[^>]+>)?` +
		`(?P<rightid>\[[^\]]+])?` +
		`(?P<rightclient>===` + lsIPNetPart + `)?;`
	lsState = `(?P<prefix>` +
		lsPrefix +
		`#(?P<serialno>\d+): ` +
		lsConnPart +
		`)` +
		`(:\d+(\(tcp\))?)?` +
		`(` + lsIPAddrPart + `)?(:[^ ]+)? `
)

var (
	reLSMarker = regexp.MustCompile(`(?m)` + lsPrefix + `Connection list:$`)
	lsStatsRE  = regexp.MustCompile(`IKE SAs: total\((\d+)\), half-open\((\d+)\)`)

	lsConnRE = regexp.MustCompile(lsConn)
	lsAddrRE = regexp.MustCompile(lsAddr)

	lsStateRE     = regexp.MustCompile(lsState)
	lsParentIDRE  = regexp.MustCompile(`; isakmp#(\d+)`)
	lsStateNameRE = regexp.MustCompile(`(STATE_\w+)`)
	lsSPIRE       = regexp.MustCompile(`([a-z]+)[?:.][a-f0-9]+@` + lsIPAddrPart)
	lsTrafficRE   = regexp.MustCompile(`(AHin|AHout|ESPin|ESPout|IPCOMPin|IPCOMPout)=(\d+)(B|KB|MB)`)
	lsUsernameRE  = regexp.MustCompile(` username=(.+)$`)
)

func scrapeLibreswan(b []byte) metric.Metrics {
	ikeSAs := make(map[string]*metric.IkeSA)
	childSAs := make(map[string]*metric.ChildSA)
	localTS := make(map[string]string)
	remoteTS := make(map[string]string)
	lines := strings.Split(string(b)+"\n", "\n")
	m := metric.Metrics{}

	for i := 0; i < len(lines); i++ {
		if matches := findNamedSubmatch(lsConnRE, lines[i]); matches != nil {
			name := matches["conname"] + matches["coninst"]
			s := strings.TrimPrefix(lines[i], matches["prefix"])
			if m := findNamedSubmatch(lsAddrRE, s); m != nil {
				localTS[name] = strings.Trim(m["leftclient"], "=")
				remoteTS[name] = strings.Trim(m["rightclient"], "=")
				localID := m["leftid"]
				if localID != "" {
					localID = strings.TrimPrefix(localID[1:len(localID)-1], "@")
				}
				remoteID := m["rightid"]
				if remoteID != "" {
					remoteID = strings.TrimPrefix(remoteID[1:len(remoteID)-1], "@")
				}
				ikeSAs[name] = &metric.IkeSA{
					Name:       name,
					LocalHost:  m["leftaddr"],
					LocalID:    localID,
					RemoteHost: m["rightaddr"],
					RemoteID:   remoteID,
					ChildSAs:   make(map[string]*metric.ChildSA),
				}
			}
		} else if matches := findNamedSubmatch(lsStateRE, lines[i]); matches != nil {
			name := matches["conname"] + matches["coninst"]
			key := matches["prefix"]
			n, _ := strconv.ParseUint(matches["serialno"], 10, 32)
			child := false
			if m := lsParentIDRE.FindStringSubmatch(lines[i]); m != nil {
				child = true
				childSAs[key] = &metric.ChildSA{
					Name: name,
					UID:  uint32(n),
				}
				if s := localTS[name]; s != "" {
					childSAs[key].LocalTS = append(childSAs[key].LocalTS, s)
				}
				if s := remoteTS[name]; s != "" {
					childSAs[key].RemoteTS = append(childSAs[key].RemoteTS, s)
				}
			}
			for ; i < len(lines); i++ {
				if strings.HasPrefix(lines[i], matches["prefix"]) {
					s := strings.TrimPrefix(lines[i], matches["prefix"])
					if child {
						if ikeSA, ok := ikeSAs[name]; ok {
							ikeSA.ChildSAs[fmt.Sprintf("%s-%d", childSAs[key].Name, childSAs[key].UID)] = childSAs[key]
						}
						if m := lsStateNameRE.FindStringSubmatch(s); m != nil {
							childSAs[key].State = m[1]
							if ikeSA, ok := ikeSAs[name]; ok {
								if strings.HasPrefix(m[1], "STATE_V2_") {
									ikeSA.Version = 2
								} else {
									ikeSA.Version = 1
								}
							}
						}
						for _, m := range lsSPIRE.FindAllStringSubmatch(s, -1) {
							if m[1] == "tun" {
								childSAs[key].Mode = "TUNNEL"
								break
							}
						}
						for _, m := range lsTrafficRE.FindAllStringSubmatch(s, -1) {
							n, _ = strconv.ParseUint(m[2], 10, 64)
							switch m[3] {
							case "MB":
								n *= 1024
								fallthrough
							case "KB":
								n *= 1024
							}
							switch m[1] {
							case "AHin", "AHout":
								childSAs[key].Protocol = "AH"
							case "ESPin", "ESPout":
								childSAs[key].Protocol = "ESP"
							case "IPCOMPin", "IPCOMPout":
								childSAs[key].Protocol = "IPCOMP"
							}
							switch strings.TrimPrefix(m[1], childSAs[key].Protocol) {
							case "in":
								childSAs[key].InBytes = n
							case "out":
								childSAs[key].OutBytes = n
							}
						}
						if m := lsUsernameRE.FindStringSubmatch(s); m != nil {
							if ikeSA, ok := ikeSAs[name]; ok {
								ikeSA.RemoteXAuthID = m[1]
							}
						}
					} else {
						if ikeSA, ok := ikeSAs[name]; ok {
							ikeSA.UID = uint32(n)
						}
						if m := lsStateNameRE.FindStringSubmatch(s); m != nil {
							if ikeSA, ok := ikeSAs[name]; ok {
								ikeSA.State = m[1]
								if strings.HasPrefix(m[1], "STATE_V2_") {
									ikeSA.Version = 2
								} else {
									ikeSA.Version = 1
								}
							}
						}
					}
				} else {
					i--
					break
				}
			}
		} else if matches := lsStatsRE.FindStringSubmatch(lines[i]); matches != nil {
			n, _ := strconv.ParseUint(matches[1], 10, 64)
			m.Stats.IKESAs.Total = n
			n, _ = strconv.ParseUint(matches[2], 10, 64)
			m.Stats.IKESAs.HalfOpen = n
		}
	}
	for _, ikeSA := range ikeSAs {
		if ikeSA.UID > 0 {
			m.IKESAs = append(m.IKESAs, ikeSA)
		}
	}

	return m
}

func findNamedSubmatch(re *regexp.Regexp, s string) map[string]string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	result := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i > 0 && name != "" {
			result[name] = m[i]
		}
	}
	return result
}
