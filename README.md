# IPsec Exporter

[![tests](https://github.com/sergeymakinen/ipsec_exporter/workflows/tests/badge.svg)](https://github.com/sergeymakinen/ipsec_exporter/actions?query=workflow%3Atests)
[![Go Reference](https://pkg.go.dev/badge/github.com/sergeymakinen/ipsec_exporter.svg)](https://pkg.go.dev/github.com/sergeymakinen/ipsec_exporter)
[![Go Report Card](https://goreportcard.com/badge/github.com/sergeymakinen/ipsec_exporter)](https://goreportcard.com/report/github.com/sergeymakinen/ipsec_exporter)
[![codecov](https://codecov.io/gh/sergeymakinen/ipsec_exporter/branch/main/graph/badge.svg)](https://codecov.io/gh/sergeymakinen/ipsec_exporter)

Export strongswan/libreswan IPsec stats to Prometheus.

To run it:

```bash
make
./ipsec_exporter [flags]
```

## Exported Metrics

| Metric | Meaning | Labels
| --- | --- | ---
| ipsec_up | Was the last scrape successful. |
| ipsec_uptime_seconds | Number of seconds since the daemon started. |
| ipsec_workers_total | Number of worker threads. |
| ipsec_idle_workers | Number of idle worker threads. |
| ipsec_active_workers | Number of threads processing jobs. |
| ipsec_queues | Number of queued jobs. | priority
| ipsec_ike_sas | Number of currently registered IKE SAs. |
| ipsec_half_open_ike_sas | Number of IKE SAs in half-open state. |
| ipsec_pool_ips_total | Number of addresses in the pool. | name, address
| ipsec_online_pool_ips | Number of leases online. | name, address
| ipsec_offline_pool_ips | Number of leases offline. | name, address
| ipsec_ike_sa_state | IKE SA state. Created: 0, connecting: 1, established: 2, passive: 3, rekeying: 4, rekeyed: 5, deleting: 6, destroying: 7. | name, uid, version, local_host, local_id, remote_host, remote_id, remote_identity, vips
| ipsec_ike_sa_established_seconds | Number of seconds since the IKE SA has been established. | name, uid, version, local_host, local_id, remote_host, remote_id, remote_identity, vips
| ipsec_child_sa_state | Child SA state. Created: 0, routed: 1, installing: 2, installed: 3, updating: 4, rekeying: 5, rekeyed: 6, retrying: 7, deleting: 8, deleted: 9, destroying: 10. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_bytes_in | Number of input bytes processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_packets_in | Number of input packets processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_bytes_out | Number of output bytes processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_packets_out | Number of output packets processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_installed_seconds | Number of seconds since the child SA has been installed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts

### Flags

```bash
./ipsec_exporter --help
```

* __`vici.address`:__ VICI socket address. Example: `unix:///var/run/charon.vici` or `tcp://127.0.0.1:4502`.
* __`vici.timeout`:__ VICI socket connect timeout.
* __`collector`:__ Collector type to scrape metrics with. `vici` or `ipsec`.
* __`ipsec.command`:__ Command to scrape IPsec metrics when the collector is configured to an `ipsec` binary.
* __`web.listen-address`:__ Address to listen on for web interface and telemetry.
* __`web.telemetry-path`:__ Path under which to expose metrics.
* __`log.level`:__ Logging level. `info` by default.
* __`log.format`:__ Set the log target and format. Example: `logger:syslog?appname=bob&local=7`
  or `logger:stdout?json=true`.

### TLS and basic authentication

The ipsec_exporter supports TLS and basic authentication.
To use TLS and/or basic authentication, you need to pass a configuration file
using the `--web.config.file` parameter. The format of the file is described
[in the exporter-toolkit repository](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).
