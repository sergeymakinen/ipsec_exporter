#!/bin/sh

set -e

rm -f /run/pluto/pluto.pid || true

/usr/libexec/ipsec/_stackmanager start
/usr/sbin/ipsec --checknss
/usr/sbin/ipsec --checknflog
/usr/libexec/ipsec/pluto --config /etc/ipsec.conf
/usr/libexec/ipsec/addconn --config /etc/ipsec.conf --autoall

sleep 2
ping -c 1 sun

exec sleep infinity
