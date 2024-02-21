#!/usr/bin/atf-sh
#
# - binary data (gzipped text)
# - src -> dest
# - src [socksified] -> proxy -> dest
# - src -> proxy -> [socksified] dest
# - Proxy on: IPv4, IPv6, DNS, UNIX
# - Dest on: IPv4, IPv6, DNS, UNIX


[ -n "${IN_COMMON:-}" ] && return
type atf_get_srcdir >/dev/null 2>&1 || atf_get_srcdir() { pwd; }
. $(atf_get_srcdir)/testlib/common.sh

try_oneshot() {
  local temp=$(mktemp -d) rc=0
  echo "oneshot: $*"
  (
    srv=$(randport)
    addr="$1" ; shift

    case "$addr" in
    unix:*) addr=unix:$temp/${addr#unix:} ;;
    esac


    if [ $# -gt 0 ] ; then
      # Do it but with a socks proxy...
      host="$2"
      case "$host" in
      unix:*) proxy=0 ; host=unix:$temp/${host#unix:} ;;
      *) proxy=$(randport) ;;
      esac
      hoses -S "$host" -P $proxy proxy &
      proxypid=$(getpids $! | xargs)
      sleep 1

      # connect or bind proxy
      case "$1" in
      --listen)
	bind="-S $host -P $proxy"
	connect=""
	;;
      --connect)
	bind=""
	connect="-S $host -P $proxy"
	;;
      esac
    else
      proxypid=''
    fi

    hoses $bind listen --exec "$addr" $srv \
	"sh -c \"(for i in 1 2 3 4 5; do fortune ; done) | tee $temp/inp \"" &
    srvpid=$(getpids $! | xargs)
    sleep 1
    hoses $connect connect "$addr" $srv > $temp/out
    qkill $proxypid $srvpid
    md5sum $temp/inp $temp/out
    [ x"$(md5sum < $temp/inp)" != x"$(md5sum < $temp/out)" ] && exit 1
    :
  ) || rc=$?
  rm -rf $temp
  return $rc
}



xt_rshot1() {
  : =descr Simple oneshot tests

  try_oneshot unix:ss$RANDOM || atf_fail "Failed oneshot1 unix"
  try_oneshot localhost || atf_fail "Failed oneshot1 DNS"
  try_oneshot 127.0.0.1 || atf_fail "Failed oneshot1 IPv4"
  try_oneshot ::1 || atf_fail "Failed oneshot1 IPv6"
  :
}

xt_rshot2() {
  : =descr oneshot tests with SOCKS5 connect

  for mode in --listen --connect
  #~ for mode in --connect
  do
    #~ for cc in  unix:ss$RANDOM
    for cc in localhost unix:ss$RANDOM 127.0.0.1 ::1
    do
      try_oneshot unix:ss$RANDOM $mode $cc || atf_fail "Failed oneshot2 unix PROXY:$mode,$cc"
      try_oneshot localhost $mode $cc || atf_fail "Failed oneshot2 DNS PROXY:$mode,$cc"
      try_oneshot 127.0.0.1 $mode $cc|| atf_fail "Failed oneshot2 IPv4 PROXY:$mode,$cc"
      try_oneshot ::1 $mode $cc|| atf_fail "Failed oneshot2 IPv6 PROXY:$mode,$cc"
    done
  done
  :
}



xatf_init
