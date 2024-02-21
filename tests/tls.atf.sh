#!/usr/bin/atf-sh
#
#  - Test ssl
#    - oneshot
#    - DNS, unix:
#  - SSL,SSL-clientauth
#    - send/recv
# - server auth only, bad server auth
#    - server+client auth, bad client auth

[ -n "${IN_COMMON:-}" ] && return
type atf_get_srcdir >/dev/null 2>&1 || atf_get_srcdir() { pwd; }
. $(atf_get_srcdir)/testlib/common.sh
in_kyua && IN_QA=true || IN_QA=false
N="
"

listener_task() {
  # Usage: listener addr port
  hoses $bind listen --exec -p $lsdest -- sh -c "set -x ; dd of=$temp/out\$\$" &
  destpid=$!
  sleep 1
}

sendsrv_task() {
  # Usage: listener addr port
  hoses $bind listen --exec -p $lsdest -- sh -c "sh -c \"(for i in 1 2 3 4 5; do fortune ; done)| tee $temp/inp\$\$\"" &
  destpid=$!
  sleep 1
}

proxy_task() {
  hoses $proxy_opts $proxy proxy &
  proxypid=$!
  sleep 1
}

client_task() {
  randtext |  tee  $temp/inp$RANDOM  | hoses $connect connect $lsdest
}
recvcln_task() {
  hoses $connect connect $lsdest | dd of=$temp/out$RANDOM
}


check_io() {
  (md5sum $temp/inp* $temp/out*|sort)
  # head $temp/inp* $temp/out*
  #~ tail $temp/inp* $temp/out*
  #~ diff --text -u $temp/inp* $temp/out*
  #~ cat -nv $temp/out*
  wc $temp/inp* $temp/out*

  for out in $temp/out*
  do
    eval z$(md5sum $out | awk '{print $1}')=\$out
  done
  for t in $temp/inp*
  do
    inp=$(md5sum $t | awk '{print $1}')
    eval out=\"\$z${inp}\"
    [ $failmode "$out" ] && return 1
  done
  :
}

try_send() {
  local temp=$(mktemp -d) rc=0
  echo "CASE: $*"
  (
    "$@"

    proxy_task
    listener_task
    client_task

    qkill $(getpids $destpid) $(getpids $proxypid)
    wait
    check_io

    exit $?
  ) || rc=$?
  rm -rf $temp
  return $rc
}

try_recv() {
  local temp=$(mktemp -d) rc=0
  echo "CASE: $*"
  (
    "$@"

    proxy_task
    sendsrv_task
    recvcln_task

    qkill $(getpids $destpid) $(getpids $proxypid)
    wait
    check_io

    exit $?
  ) || rc=$?
  rm -rf $temp
  return $rc
}


case_1() {
  echo "$*" : "server check only"

  #~ local proxy_host=localhost proxy_port=$(randport)
  local proxy_host=unix:$temp/socket proxy_port=0

  local server=$temp/server
  set -x
  newcert "/CN=$(fixunixcn ${proxy_host})" $server
  set +x

  lsdest="localhost $(randport)"
  #~ lsdest="unix 0"
  #~ bind="$proxy_srv "

  proxy="-S $proxy_host -P $proxy_port --cert=$server.crt --key=$server.key"

  connect="-S $proxy_host -P $proxy_port --ca=$server.crt"

  failmode="-z"
}

case_1bad() {
  echo "$*" : "server check only BAD CERT"

  #~ local proxy_host=localhost proxy_port=$(randport)
  local proxy_host=unix:$temp/socket proxy_port=0

  local server=$temp/server
  newcert "/CN=$(fixunixcn ${proxy_host})" $server
  newcert "/CN=$(fixunixcn ${proxy_host})" ${server}_alt

  lsdest="localhost $(randport)"
  #~ lsdest="unix 0"
  #~ bind="$proxy_srv "

  proxy="-S $proxy_host -P $proxy_port --cert=$server.crt --key=$server.key"

  connect="-S $proxy_host -P $proxy_port --ca=${server}_alt.crt"

  failmode="-n"
}


case_2() {
  echo "$*" : "server and client checks"

  local proxy_host=localhost proxy_port=$(randport)
  #~ local proxy_host=unix:$temp/socket proxy_port=0

  local client=$temp/client
  local server=$temp/server
  newcert "/CN=$(fixunixcn ${proxy_host})" $server
  newcert "/CN=labrat/emailAddress=labrat@test.lab" $client

  lsdest="localhost $(randport)"
  #~ lsdest="unix 0"
  #~ bind="$proxy_srv "

  proxy="-S $proxy_host -P $proxy_port --cert=$server.crt --key=$server.key --ca=$client.crt"
  connect="-S $proxy_host -P $proxy_port --cert=$client.crt --key=$client.key --ca=$server.crt"

  failmode="-z"
}
case_2bad() {
  echo "$*" : "server and client checks, client cert error"

  local proxy_host=localhost proxy_port=$(randport)
  #~ local proxy_host=unix:$temp/socket proxy_port=0

  local client=$temp/client
  local server=$temp/server
  newcert "/CN=$(fixunixcn ${proxy_host})" $server
  newcert "/CN=labrat/emailAddress=labrat@test.lab" $client
  newcert "/CN=bad/emailAddress=abdc@test.lab" ${client}_bad

  lsdest="localhost $(randport)"
  #~ lsdest="unix 0"
  #~ bind="$proxy_srv "

  proxy="-S $proxy_host -P $proxy_port --cert=$server.crt --key=$server.key --ca=${client}_bad.crt"
  connect="-S $proxy_host -P $proxy_port --cert=$client.crt --key=$client.key --ca=$server.crt"

  failmode="-n"
}



xt_send1() {
  : =descr try#1
  try_send case_1 "$@" || atf_fail "send case1"
  :
}
xt_recv1() {
  : =descr try#1
  try_recv case_1 "$@" || atf_fail "recv case1"
  :
}
xt_send1bad() {
  : =descr try#1 bad
  try_send case_1bad"$@" || atf_fail "send case1"
  :
}


xt_send2() {
  : =descr try#2
  try_send case_2 "$@" || atf_fail "send case2"
  :
}
xt_recv2() {
  : =descr try#2
  try_recv case_2 "$@" || atf_fail "recv case2"
  :
}
xt_send2bad() {
  : =descr try#2 bad
  try_send case_2bad "$@" || atf_fail "send case2"
  :
}






#~ $IN_QA || f="xt_z_all() {$N: =descr multi portfwd tests"
#~ for lsdest in "localhost $(randport)" "unix 0"
#~ do
  #~ lsname=$(echo $lsdest | awk '{print $1}')
  #~ for portfwd in "localhost $(randport)" "unix 0"
  #~ do
    #~ pfname=$(echo $portfwd | awk '{print $1}')
    #~ for fwd_opts in "" "-p"
    #~ do
      #~ pfoname=$(echo $fwd_opts | tr 'x-' 'x_')
      #~ for proxy in '' "-S localhost -P $(randport)"
      #~ do
	#~ if [ -n "$proxy" ] ; then
	  #~ proxyname="_proxied_"
	#~ else
	  #~ proxyname="_"
	#~ fi
	#~ fn=xt_pf${proxyname}${pfoname}${pfname}_${lsname}

	#~ eval "${fn}() {
	    #~ lsdest='$lsdest'
	    #~ portfwd='$portfwd'
	    #~ fwd_opts='$fwd_opts'
	    #~ proxy='$proxy'
	    #~ try_case $proxy $fwd_opts $portfwd $lsdest || atf_fail 'listen=$lsdest pf=$portfwd fo=$fwd_opts proxy=$proxy'
	    #~ :
	  #~ }"
	#~ $IN_QA || f="$f$N echo $fn; $fn"
      #~ done
    #~ done
  #~ done
#~ done

#~ $IN_QA || { f="$f${N}}" ;  eval "$f"; }



xatf_init
