#!/bin/sh

: <<-_EOF_
  - stunnel
    - wrap/unwrap
    -
  - ??good cert, bad cert - accept rule, patt mach deny rule??

_EOF_

# Test using hoses-connect as a proxy command
type atf_get_srcdir >/dev/null 2>&1 || atf_get_srcdir() { pwd; }
. $(atf_get_srcdir)/testlib/common.sh

tt_listener_eliza() {
  local srv=$(randport)
  hoses listen --exec localhost $srv -- sh -c 'cd eliza ; python3 eliza.py' &
  srv_pid=$!
  echo "Running as $srv_pid"
  sleep 1
  randtext | hoses connect localhost $srv
  qkill $srv_pid
}
#~ tt_listener_eliza

tt_proxied_eliza() {
  local srv=$(randport) addr=127.0.0.1
  hoses listen --exec $addr $srv -- sh -c 'cd eliza ; python3 eliza.py' &
  srv_pid=$(getpids $! | xargs)

  #~ local proxy="-S localhost -P $(randport)"
  #~ local proxy="-S ::1 -P $(randport)"
  local proxy="-S unix:socket -P 0"
  hoses $proxy proxy -l audit.log &
  proxy_pid=$(getpids $! | xargs)

  sleep 1

  hoses $proxy connect $addr $srv

  qkill  $proxy_pid $srv_pid
}
#~ tt_proxied_eliza

tt_rproxied_eliza() {
  local proxy=$(randport)
  hoses -S localhost -P $proxy proxy &
  proxy_pid=$(getpids $! | xargs)

  local srv=$(randport)
  hoses -S localhost -P $proxy listen --exec localhost $srv tee out &
  srv_pid=$(getpids $! | xargs)

  sleep 1

  randtext | hoses connect localhost $srv

  qkill  $proxy_pid $srv_pid
}
#~ tt_rproxied_eliza

tt_certs() {
  newcert "/CN=localhost" server
  newcert "/CN=labrat/emailAddress=labrat@test.lab/DC=one/DC=two/DC=three" client
}

tt_selfsigned() {
  local srv=$(randport)
  tt_certs
  hoses listen --exec localhost $srv 'sh -c "cd eliza; python3 eliza.py"' &
  srv_pid=$!

  local proxy="-S localhost -P $(randport)"
  #~ local proxy="-S unix:socket -P 0"
  hoses $proxy \
	--cert=server.crt --key=server.key \
	--ca=client.crt \
	--log-opt level=DEBUG \
	proxy &
  proxy_pid=$!

  sleep 1

  hoses $proxy \
	--ca=server.crt \
	--cert=client.crt --key=client.key \
	connect localhost $srv

  qkill  $proxy_pid $srv_pid
}

tt_portfwd_eliza_f() {
  eliza=$(randport)
  hoses listen -p --exec localhost $eliza -- sh -c "cd eliza ; python3 eliza.py" &
  elizapid=$!
  echo eliza on $eliza pid=$elizapid

  portfwd=$(randport)
  hoses listen -p localhost $portfwd localhost $eliza &
  pfpid=$!
  echo portfwd on $portfwd pid=$pfpid

}

tt_stunnel_unwrap() {
  local srv=$(randport)
  tt_certs
  hoses \
	--cert=server.crt --key=server.key \
	--ca=client.crt \
	listen --unwrap --exec localhost $srv 'sh -c "cd eliza; python3 eliza.py"' &
  srv_pid=$!
  sleep 1

  hoses  \
	--ca=server.crt \
	--cert=client.crt --key=client.key \
	connect --tls localhost $srv

  qkill  $srv_pid
}

tt_stunnel_wrap() {
  local srv=$(randport)
  tt_certs
  hoses \
	--cert=server.crt --key=server.key \
	--ca=client.crt \
	listen --unwrap --exec localhost $srv 'sh -c "cd eliza; python3 eliza.py"' &
  srv_pid=$!
  sleep 1

  local tunnel=$(randport)
  hoses \
	--ca=server.crt \
	--cert=client.crt --key=client.key \
	listen --wrap localhost $tunnel \
		      localhost $srv &
  tunnel_pid=$!
  sleep 1

  hoses connect  localhost $tunnel

  qkill  $srv_pid $tunnel_pid
}



if [ $# -eq 0 ] ; then
  declare -F | awk '$3 ~ /^tt_/ {print $3}'
else
  "$@"
fi

# netcat
# inetd

