#!/usr/bin/atf-sh
#
# Test --background and --persist modes
#
# -  src -> dest
#   - src->dest multiple : IPv4, IPv6, DNS, UNIX
# - src -> proxy -> [socksified] dest
#   - multiple : IPv4, IPv6, DNS, UNIX
#
[ -n "${IN_COMMON:-}" ] && return
type atf_get_srcdir >/dev/null 2>&1 || atf_get_srcdir() { pwd; }
. $(atf_get_srcdir)/testlib/common.sh

in_kyua && IN_QA=true || IN_QA=false
N="
"

try_multishot1() {
  local temp=$(mktemp -d) rc=0
  echo "Multishot $*" 1>&2
  (
    srv=$(randport)
    addr="$1" ; shift
    case "$addr" in
    unix:*) set - "unix:$temp/${addr#unix:}" ; srv=0 ;;
    esac

    if [ $# -gt 0 ] ; then
      # Enable socks proxy
      host="$2"
      case "$host" in
      unix:*) proxy=0 ; host=unix:$temp/${host#unix:} ;;
      *) proxy=$(randport) ;;
      esac
      hoses -S "$host" -P $proxy proxy &
      proxypid=$!
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
      bind=""
      connect=""
    fi

    ( # Wait for connections
      t=1
      while true
      do
	echo "Server $t: waiting"
	hoses $bind listen -f --exec "$addr" $srv \
	  "sh -c \"set -x ; dd of=$temp/out$t\"" &
	echo $! > $temp/lastpid
	wait
	echo "Server $t: running in background"
	t=$(($t + 1))
      done
    ) &
    srvpid=$!
    sleep 1

    n=5
    (
      for t in $(seq 1 $n)
      do
	sleep 0.5
	(randtext | sed -e 's/^/:/' | (
	    exec 3> $temp/inp$t
	    while read ln
	    do
	      echo "$ln"
	      echo "$ln" 1>&3
	      sleep 0.02
	    done
	  ) | hoses $connect connect "$addr" $srv
	) &
      done
      echo "Threadsd spawned: $n"
      wait
    )
    # Clean-up processes
    qkill $(getpids $srvpid|xargs) $(getpids $proxypid | xargs)
    wait
    cat $temp/lastpid
    #~ ps ax | grep python3

    for t in $(seq 1 $n)
    do
      a=$(md5sum < $temp/inp$t)
      b=$(md5sum < $temp/out$t)
      echo $t: $a $b
      [ x"$a" != x"$b" ] && exit 1
    done
    :
  ) || rc=$?
  rm -rf $temp
  return $rc
}

$IN_QA || f="xt_zmulti1() {$N: =descr multishot bundle"

for target in localhost unix:ss 127.0.0.1 ::1
do
  tname=$(echo $target | tr ':.' '__')
  $IN_QA || f="$f${N}xt_multishot1_${tname}"

  eval "xt_multishot1_${tname}() {
    : =descr multishot1 to $target
    try_multishot1 $target || atf_fail 'Failed multishot1 $target'
  }"
done
$IN_QA || { f="$f${N}}" ;  eval "$f" ; }

for cc in localhost unix:ss 127.0.0.1 ::1
do
  ccname=$(echo $cc | tr ':.' '__')
  $IN_QA || f="xt_zmulti1p_${ccname}() {$N: =descr multishot $cc proxy bundle"
  for target in localhost unix:ss 127.0.0.1 ::1
  do
    tname=$(echo $target | tr ':.' '__')
    $IN_QA || f="$f${N}xt_multishot1p_${ccname}_${tname}"
    eval "xt_multishot1p_${ccname}_${tname}() {
      : =descr multishot1 proxy $cc to $target
      try_multishot1 $target --listen $cc || atf_fail 'Failed multishot1 proxied $cc to $target'
    }"
  done
  $IN_QA || { f="$f${N}}" ;  eval "$f"; }
done

try_multishot2() {
  local temp=$(mktemp -d) rc=0
  echo "Multishot $*" 1>&2
  (
    addr="$1"
    srv=$(randport)
    case "$addr" in
    unix:*) set - "unix:$temp/${addr#unix:}" ; srv=0 ;;
    esac

    if [ $# -gt 0 ] ; then
      # Enable socks proxy
      host="$2"
      case "$host" in
      unix:*) proxy=0 ; host=unix:$temp/${host#unix:} ;;
      *) proxy=$(randport) ;;
      esac
      hoses -S "$host" -P $proxy proxy &
      proxypid=$!
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
      bind=""
      connect=""
    fi

    # Wait for connections
    hoses $bind listen -p --exec "$addr" $srv \
	  "sh -c \"set -x ; dd of=$temp/out\$\$\"" &
    srvpid=$!
    sleep 1

    n=5
    (
      for t in $(seq 1 $n)
      do
	sleep 0.1
	(
	  echo "Spawning $t"
	  randtext | sed -e 's/^/:/' | (
	    exec 3> $temp/inp$t
	    while read ln
	    do
	      echo "$ln"
	      echo "$ln" 1>&3
	      sleep 0.02
	    done
	  ) | hoses $connect connect "$addr" $srv
	  echo "Closed $t"
	) &
      done
      wait
    )
    # Clean-up processes
    qkill $(getpids $srvpid | xargs)  $(getpids $proxypid | xargs)
    wait

    (md5sum $temp/inp*
    md5sum $temp/out*)|sort

    for out in $temp/out*
    do
      eval z$(md5sum $out | awk '{print $1}')=\$out
    done

    for t in $(seq 1 $n)
    do
      inp=$(md5sum $temp/inp$t | awk '{print $1}')
      eval out=\"\$z${inp}\"
      if [ -z "$out" ] ; then
        exit 1
      fi
    done
    :
  ) || rc=$?
  rm -rf $temp
  return $rc
}

#~ xt_multishot2() {
  #~ : =descr multishot2

  #~ for mode in "" "--listen"
  #~ do
    #~ for cc in localhost # unix:ss$RANDOM 127.0.0.1 ::1
    #~ do
      #~ try_multishot2 localhost $mode $cc|| atf_fail "Failed multishot2 DNS $mode $cc"
      #~ try_multishot2 unix:ss$RANDOM $mode $cc || atf_fail "Failed multishot2 unix $mode $cc"
      #~ try_multishot2 127.0.0.1 $mode $cc || atf_fail "Failed multishot2 IPv4 $mode $cc"
      #~ try_multishot2 ::1 $mode $cc || atf_fail "Failed multishot2 IPv6 $mode $cc"
    #~ done
  #~ done
  #~ :
#~ }

$IN_QA || f="xt_zmulti2() {$N: =descr multishot2 bundle"

for target in localhost unix:ss 127.0.0.1 ::1
do
  tname=$(echo $target | tr ':.' '__')
  $IN_QA || f="$f${N}xt_multishot2_${tname}"

  eval "xt_multishot2_${tname}() {
    : =descr multishot2 to $target
    try_multishot2 $target || atf_fail 'Failed multishot2 $target'
  }"
done
$IN_QA || { f="$f${N}}" ;  eval "$f" ; }

for cc in localhost unix:ss 127.0.0.1 ::1
do
  ccname=$(echo $cc | tr ':.' '__')
  $IN_QA || f="xt_zmulti2p_${ccname}() {$N: =descr multishot2 $cc proxy bundle"
  for target in localhost unix:ss 127.0.0.1 ::1
  do
    tname=$(echo $target | tr ':.' '__')
    $IN_QA || f="$f${N}xt_multishot2p_${ccname}_${tname}"
    eval "xt_multishot2p_${ccname}_${tname}() {
      : =descr multishot2 proxy $cc to $target
      try_multishot2 $target --listen $cc || atf_fail 'Failed multishot2 proxied $cc to $target'
    }"
  done
  $IN_QA || { f="$f${N}}" ;  eval "$f"; }
done


xatf_init
