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

## Exported metrics

### Exported for both strongswan/libreswan

| Metric | Meaning | Labels
| --- | --- | ---
| ipsec_up | Was the last scrape successful. |
| ipsec_ike_sas | Number of currently registered IKE SAs. |
| ipsec_half_open_ike_sas | Number of IKE SAs in half-open state. |
| ipsec_ike_sa_state | IKE SA state. | name, uid, version, local_host, local_id, remote_host, remote_id, remote_identity, vips
| ipsec_child_sa_state | Child SA state. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_bytes_in | Number of input bytes processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_bytes_out | Number of output bytes processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts

### Additionally exported for strongswan-only

| Metric | Meaning | Labels
| --- | --- | ---
| ipsec_uptime_seconds | Number of seconds since the daemon started. |
| ipsec_workers_total | Number of worker threads. |
| ipsec_idle_workers | Number of idle worker threads. |
| ipsec_active_workers | Number of threads processing jobs. |
| ipsec_queues | Number of queued jobs. | priority
| ipsec_pool_ips_total | Number of addresses in the pool. | name, address
| ipsec_online_pool_ips | Number of leases online. | name, address
| ipsec_offline_pool_ips | Number of leases offline. | name, address
| ipsec_ike_sa_established_seconds | Number of seconds since the IKE SA has been established. | name, uid, version, local_host, local_id, remote_host, remote_id, remote_identity, vips
| ipsec_child_sa_packets_in | Number of input packets processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_packets_out | Number of output packets processed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts
| ipsec_child_sa_installed_seconds | Number of seconds since the child SA has been installed. | ike_sa_name, ike_sa_uid, ike_sa_version, ike_sa_local_host, ike_sa_local_id, ike_sa_remote_host, ike_sa_remote_id, ike_sa_remote_identity, ike_sa_vips, name, uid, reqid, mode, protocol, local_ts, remote_ts

### strongswan state mapping

#### IKE SA

| Name | State value
| --- | ---
| CREATED | 0
| CONNECTING | 1
| ESTABLISHED | 2
| PASSIVE | 3
| REKEYING | 4
| REKEYED | 5
| DELETING | 6
| DESTROYING | 7

#### Child SA

| Name | State value
| --- | ---
| CREATED | 0
| ROUTED | 1
| INSTALLING | 2
| INSTALLED | 3
| UPDATING | 4
| REKEYING | 5
| REKEYED | 6
| RETRYING | 7
| DELETING | 8
| DELETED | 9
| DESTROYING | 10

### libreswan state mapping

| Name | State value
| --- | ---
| STATE_MAIN_R0 | 0
| STATE_MAIN_I1 | 1
| STATE_MAIN_R1 | 2
| STATE_MAIN_I2 | 3
| STATE_MAIN_R2 | 4
| STATE_MAIN_I3 | 5
| STATE_MAIN_R3 | 6
| STATE_MAIN_I4 | 7
| STATE_AGGR_R0 | 8
| STATE_AGGR_I1 | 9
| STATE_AGGR_R1 | 10
| STATE_AGGR_I2 | 11
| STATE_AGGR_R2 | 12
| STATE_QUICK_R0 | 13
| STATE_QUICK_I1 | 14
| STATE_QUICK_R1 | 15
| STATE_QUICK_I2 | 16
| STATE_QUICK_R2 | 17
| STATE_INFO | 18
| STATE_INFO_PROTECTED | 19
| STATE_XAUTH_R0 | 20
| STATE_XAUTH_R1 | 21
| STATE_MODE_CFG_R0 | 22
| STATE_MODE_CFG_R1 | 23
| STATE_MODE_CFG_R2 | 24
| STATE_MODE_CFG_I1 | 25
| STATE_XAUTH_I0 | 26
| STATE_XAUTH_I1 | 27
| STATE_V2_PARENT_I0 | 29
| STATE_V2_PARENT_I1 | 30
| STATE_V2_PARENT_I2 | 31
| STATE_V2_PARENT_R0 | 32
| STATE_V2_PARENT_R1 | 33
| STATE_V2_IKE_AUTH_CHILD_I0 | 34
| STATE_V2_IKE_AUTH_CHILD_R0 | 35
| STATE_V2_NEW_CHILD_I0 | 36
| STATE_V2_NEW_CHILD_I1 | 37
| STATE_V2_REKEY_IKE_I0 | 38
| STATE_V2_REKEY_IKE_I1 | 39
| STATE_V2_REKEY_CHILD_I0 | 40
| STATE_V2_REKEY_CHILD_I1 | 41
| STATE_V2_NEW_CHILD_R0 | 42
| STATE_V2_REKEY_IKE_R0 | 43
| STATE_V2_REKEY_CHILD_R0 | 44
| STATE_V2_ESTABLISHED_IKE_SA | 45
| STATE_V2_ESTABLISHED_CHILD_SA | 46
| STATE_V2_IKE_SA_DELETE | 47
| STATE_V2_CHILD_SA_DELETE | 48

## Flags

```bash
./ipsec_exporter --help
```

* __`vici.address`:__ VICI socket address. Example: `unix:///var/run/charon.vici` or `tcp://127.0.0.1:4502`.
* __`vici.timeout`:__ VICI socket connect timeout.
* __`collector`:__ Collector type to scrape metrics with. `vici` or `ipsec`.
* __`ipsec.command`:__ Command to scrape IPsec metrics when the collector is configured to an `ipsec` binary. `ipsec statusall` by default.
  To use with libreswan, set to `ipsec status`.
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
