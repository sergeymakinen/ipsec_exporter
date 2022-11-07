package ipsecmetrics

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/spheromak/ipsec_exporter/pkg/metric"
)

const (
	ssPrefixStatus = "Status of IKE charon daemon"
	ssPrefixPools  = "Virtual IP pools (size/online/offline):"
	ssPrefixSA     = "Security Associations"
)

var (
	reSSMarker = regexp.MustCompile(`(?m)` + ssSAHeaderRE.String())

	ssIKESAStates = map[string]float64{
		"CREATED":     0,
		"CONNECTING":  1,
		"ESTABLISHED": 2,
		"PASSIVE":     3,
		"REKEYING":    4,
		"REKEYED":     5,
		"DELETING":    6,
		"DESTROYING":  7,
	}
	ssChildSAStates = map[string]float64{
		"CREATED":    0,
		"ROUTED":     1,
		"INSTALLING": 2,
		"INSTALLED":  3,
		"UPDATING":   4,
		"REKEYING":   5,
		"REKEYED":    6,
		"RETRYING":   7,
		"DELETING":   8,
		"DELETED":    9,
		"DESTROYING": 10,
	}
)

var (
	ssUptimeRE           = regexp.MustCompile(`^  uptime: .+, since (.+)$`)
	ssStatsRE            = regexp.MustCompile(`^  worker threads: (\d+) of (\d+) idle, (\d+)/(\d+)/(\d+)/(\d+) working, job queue: (\d+)/(\d+)/(\d+)/(\d+), scheduled: (\d+)$`)
	ssPoolRE             = regexp.MustCompile(`^  (.+?): (\d+)/(\d+)/(\d+)$`)
	ssSAHeaderRE         = regexp.MustCompile(`^Security Associations \((\d+) up, (\d+) connecting\):$`)
	ssSAPrefixRE         = regexp.MustCompile(`^\s*([^\[]+)\[(\d+)]: `)
	ssSAStatusRE         = regexp.MustCompile(`^([^ ]+) .+ ago, ([^\[]+)\[([^]]+)]\.\.\.([^\[]+)\[([^]]+)]$`)
	ssSAVersionRE        = regexp.MustCompile(`^(.+) SPIs:`)
	ssSARemoteIdentityRE = regexp.MustCompile(`^Remote (.+) identity: (.+)$`)
	ssChildSAPrefixRE    = regexp.MustCompile(`^\s*([^{]+){(\d+)}:  `)
	ssChildSAStatusRE    = regexp.MustCompile(`^([^,]+), ([^,]+), reqid (\d+), (.+) SPIs:.+`)
	ssChildSATrafficRE   = regexp.MustCompile(`(\d+) bytes_i(?: \((\d+) pkts?[^)]*\))?, (\d+) bytes_o(?: \((\d+) pkts?[^)]*\))?`)
	ssChildSATSRE        = regexp.MustCompile(`^ (.+) === (.+)$`)
)

func scrapeStrongswan(b []byte) (m metric.Metrics) {
	// Looking for prefixes then scanning lines below for matching regexps
	lines := strings.Split(string(b)+"\n", "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, ssPrefixStatus):
			j := i
			if i+1 < len(lines) {
				j++
			}
			for _, line := range lines[j:] {
				if !strings.HasPrefix(line, "  ") {
					break
				}
				matches := ssUptimeRE.FindStringSubmatch(line)
				if matches != nil {
					m.Stats.Uptime.Since = matches[1]
					continue
				}
				matches = ssStatsRE.FindStringSubmatch(line)
				if matches != nil {
					m.Stats.Workers = &metric.Workers{}
					m.Stats.Workers.Idle, _ = strconv.ParseUint(matches[1], 10, 64)
					m.Stats.Workers.Total, _ = strconv.ParseUint(matches[2], 10, 64)
					m.Stats.Workers.Active.Critical, _ = strconv.ParseUint(matches[3], 10, 64)
					m.Stats.Workers.Active.High, _ = strconv.ParseUint(matches[4], 10, 64)
					m.Stats.Workers.Active.Medium, _ = strconv.ParseUint(matches[5], 10, 64)
					m.Stats.Workers.Active.Low, _ = strconv.ParseUint(matches[6], 10, 64)
					m.Stats.Queues = &metric.Queues{}
					m.Stats.Queues.Critical, _ = strconv.ParseUint(matches[7], 10, 64)
					m.Stats.Queues.High, _ = strconv.ParseUint(matches[8], 10, 64)
					m.Stats.Queues.Medium, _ = strconv.ParseUint(matches[9], 10, 64)
					m.Stats.Queues.Low, _ = strconv.ParseUint(matches[10], 10, 64)
					n, _ := strconv.ParseUint(matches[11], 10, 64)
					m.Stats.Scheduled = &n
				}
			}
		case line == ssPrefixPools:
			j := i
			if i+1 < len(lines) {
				j++
			}
			for _, line := range lines[j:] {
				matches := ssPoolRE.FindStringSubmatch(line)
				if matches == nil {
					break
				}
				pool := metric.Pool{Address: matches[1]}
				pool.Size, _ = strconv.ParseUint(matches[2], 10, 64)
				pool.Online, _ = strconv.ParseUint(matches[3], 10, 64)
				pool.Offline, _ = strconv.ParseUint(matches[4], 10, 64)
				m.Pools = append(m.Pools, pool)
			}
		case strings.HasPrefix(line, ssPrefixSA):
			matches := ssSAHeaderRE.FindStringSubmatch(line)
			if matches != nil {
				m.Stats.IKESAs.Total, _ = strconv.ParseUint(matches[1], 10, 64)
				m.Stats.IKESAs.HalfOpen, _ = strconv.ParseUint(matches[2], 10, 64)
				j := i
				if i+1 < len(lines) {
					j++
				}
				var (
					prefix, childPrefix []string
					sa, prevSA          *metric.IkeSA
					childSA2            *metric.ChildSA
				)

			Loop:
				for _, line := range lines[j:] {
					if (prefix != nil && !strings.HasPrefix(line, prefix[0])) || (childPrefix != nil && !strings.HasPrefix(line, childPrefix[0])) {
						if sa != nil {
							prevSA = sa
						}
						prefix, childPrefix, sa, childSA2 = nil, nil, nil, nil
					}
					if prefix == nil && childPrefix == nil {
						matches = ssSAPrefixRE.FindStringSubmatch(line)
						if matches != nil {
							prefix = matches
							sa = &metric.IkeSA{
								Name:     matches[1],
								ChildSAs: make(map[string]*metric.ChildSA),
							}
							n, _ := strconv.ParseUint(matches[2], 10, 32)
							sa.UID = uint32(n)
							m.IKESAs = append(m.IKESAs, sa)

						} else {
							matches = ssChildSAPrefixRE.FindStringSubmatch(line)
							if matches != nil {
								childPrefix = matches
								childSA2 = &metric.ChildSA{Name: matches[1]}
								n, _ := strconv.ParseUint(matches[2], 10, 32)
								childSA2.UID = uint32(n)
								if prevSA != nil {
									prevSA.ChildSAs[fmt.Sprintf("%s-%d", childSA2.Name, childSA2.UID)] = childSA2
								}
							}
						}
					}
					switch {
					case prefix != nil:
						line = strings.TrimPrefix(line, prefix[0])
						matches = ssSAStatusRE.FindStringSubmatch(line)
						if matches != nil {
							sa.State = matches[1]
							sa.LocalHost = matches[2]
							sa.LocalID = matches[3]
							sa.RemoteHost = matches[4]
							sa.RemoteID = matches[5]
							continue
						}
						matches = ssSAVersionRE.FindStringSubmatch(line)
						if matches != nil {
							switch matches[1] {
							case "IKEv1":
								sa.Version = 1
							case "IKEv2":
								sa.Version = 2
							}
							continue
						}
						matches = ssSARemoteIdentityRE.FindStringSubmatch(line)
						if matches != nil {
							if matches[1] == "XAuth" {
								sa.RemoteXAuthID = matches[2]
							} else {
								sa.RemoteEAPID = matches[2]
							}
						}
					case childPrefix != nil:
						line = strings.TrimPrefix(line, childPrefix[0])
						matches = ssChildSAStatusRE.FindStringSubmatch(line)
						if matches != nil {
							childSA2.State = matches[1]
							childSA2.Mode = matches[2]
							n, _ := strconv.ParseUint(matches[3], 10, 64)
							u := uint32(n)
							childSA2.ReqID = &u
							childSA2.Protocol = matches[4]
							continue
						}
						matches = ssChildSATrafficRE.FindStringSubmatch(line)
						if matches != nil {
							childSA2.InBytes, _ = strconv.ParseUint(matches[1], 10, 64)
							childSA2.OutBytes, _ = strconv.ParseUint(matches[3], 10, 64)
							if matches[2] != "" && matches[4] != "" {
								n, _ := strconv.ParseUint(matches[2], 10, 64)
								childSA2.InPackets = &n
								n, _ = strconv.ParseUint(matches[4], 10, 64)
								childSA2.OutPackets = &n
							}
							continue
						}
						matches = ssChildSATSRE.FindStringSubmatch(line)
						if matches != nil {
							childSA2.LocalTS = strings.Split(matches[1], " ")
							childSA2.RemoteTS = strings.Split(matches[2], " ")
						}
					default:
						break Loop
					}
				}
			}
		}
	}
	return
}
