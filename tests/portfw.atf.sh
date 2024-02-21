#!/usr/bin/atf-sh
#
#  - connect -> [socksified?] dest-port-fwd -> listen
#    - oneshot, bg, persist
#    - DNS, unix:
#

[ -n "${IN_COMMON:-}" ] && return
type atf_get_srcdir >/dev/null 2>&1 || atf_get_srcdir() { pwd; }
. $(atf_get_srcdir)/testlib/common.sh
in_kyua && IN_QA=true || IN_QA=false
N="
"

listener_task() {
  # Usage: listener addr port
  hoses listen --exec -p $lsdest -- sh -c "set -x ; dd of=$temp/out\$\$" &
  destpid=$!
  sleep 1
}

portfwd_task() {
  hoses $proxy listen $fwd_opts $portfwd $lsdest &
  portfwpid=$!
  sleep 1
}

proxy_task() {
  hoses $proxy --log-opt level=DEBUG proxy &
  proxypid=$!
  sleep 1
}

client_task() {
  randtext | tee  $temp/inp$RANDOM | hoses $connect connect $portfwd
}

try_case() {
  local temp=$(mktemp -d) rc=0
  echo "CASE: $*"
  (
    for i in lsdest portfwd
    do
      eval j=\"\$$i\"
      case "$j" in
      unix*)
        j="unix:$temp/$RANDOM 0"
	eval "${i}=\"\$j\""
	;;
      esac
    done

    listener_task
    [ -n "$proxy" ] && proxy_task

    portfwd_task

    client_task
    if [ x"$fwd_opts" = x"-p" ] ; then
      #~ sleep 1
      #~ ps ax | awk -vpty=pts/0 '$2 == pty && $5 == "python3" {print}'
      client_task
    fi

    echo $destpid,$portfwpid,$proxypid
    qkill $(getpids $destpid) $(getpids $portfwpid) $(getpids $proxypid)
    wait

    for out in $temp/out*
    do
      eval z$(md5sum $out | awk '{print $1}')=\$out
    done

    for t in $temp/inp*
    do
      inp=$(md5sum $t | awk '{print $1}')
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

# lsdest="localhost $(randport)"
# lsdest="unix 0"

# portfwd="localhost $(randport)"
# portfwd="unix 0"

# fwd_opts=""
# fwd_opts="-p"

# proxy=""
# proxy="-S localhsot -P $(randport)"


$IN_QA || f="xt_z_all() {$N: =descr multi portfwd tests"
for lsdest in "localhost $(randport)" "unix 0"
do
  lsname=$(echo $lsdest | awk '{print $1}')
  for portfwd in "localhost $(randport)" "unix 0"
  do
    pfname=$(echo $portfwd | awk '{print $1}')
    for fwd_opts in "" "-p"
    do
      pfoname=$(echo $fwd_opts | tr 'x-' 'x_')
      for proxy in '' "-S localhost -P $(randport)"
      do
	if [ -n "$proxy" ] ; then
	  proxyname="_proxied_"
	else
	  proxyname="_"
	fi
	fn=xt_pf${proxyname}${pfoname}${pfname}_${lsname}

	eval "${fn}() {
	    lsdest='$lsdest'
	    portfwd='$portfwd'
	    fwd_opts='$fwd_opts'
	    proxy='$proxy'
	    try_case $proxy $fwd_opts $portfwd $lsdest || atf_fail 'listen=$lsdest pf=$portfwd fo=$fwd_opts proxy=$proxy'
	    :
	  }"
	$IN_QA || f="$f$N echo $fn; $fn"
      done
    done
  done
done

$IN_QA || { f="$f${N}}" ;  eval "$f"; }



xatf_init
