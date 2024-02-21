#!/usr/bin/atf-sh
#
# Tunnel SSH
#
# - ssh - sshd
# - ssh{proxy connect} - sshd
# - ssh{proxy connect} - proxy - sshd
# - ssh - proxy - {listener} - sshd


[ -n "${IN_COMMON:-}" ] && return
type atf_get_srcdir >/dev/null 2>&1 || atf_get_srcdir() { pwd; }
. $(atf_get_srcdir)/testlib/common.sh


xt_ssh_sshd() {
  : =descr "direct ssh to sshd test (baseline)"

  local temp=$(mktemp -d) rc=0 keyfile=$(mktemp -p "$(get_user_ssh_dir)")
  (
    srv=$(randport)
    sshd_debug $srv $temp
    canary=$RANDOM
    recv=$(ssh_debug -p $srv localhost echo $canary)
    qkill $sshpid
    [ x"$canary" != x"$recv" ] && exit 1
    :
  ) || rc=$?
  rm -rf $temp $keyfile $keyfile.pub
  [ $rc -gt 0 ] && atf_fail "ERROR baseline ssh test"
  :
}

xt_ssh_sshd_proxycmd() {
  : =descr "direct ssh to sshd test using proxy command"

  local temp=$(mktemp -d) rc=0 keyfile=$(mktemp -p "$(get_user_ssh_dir)")
  (
    srv=$(randport)
    sshd_debug $srv $temp
    canary=$RANDOM
    recv=$(ssh_debug -p $srv \
	  -o "ProxyCommand python3 $SRC_DIR/__main__.py connect %h %p" \
	  localhost echo $canary)
    qkill $sshpid
    [ x"$canary" != x"$recv" ] && exit 1
    :
  ) || rc=$?
  rm -rf $temp $keyfile $keyfile.pub
  [ $rc -gt 0 ] && atf_fail "ERROR proxycmd ssh test"
  :
}

xt_ssh_sshd_proxied_connect() {
  : =descr "proxied ssh to sshd test using"

  local temp=$(mktemp -d) rc=0 keyfile=$(mktemp -p "$(get_user_ssh_dir)")
  (
    srv=$(randport)
    sshd_debug $srv $temp
    proxy="-S unix:$temp/ss$RANDOM -P 0"

    hoses $proxy proxy &
    proxypid=$!
    sleep 1

    canary=$RANDOM
    recv=$(ssh_debug -p $srv \
	  -o "ProxyCommand python3 $SRC_DIR/__main__.py $proxy connect %h %p" \
	  localhost echo $canary)
    qkill $sshpid $(getpids $proxypid)
    [ x"$canary" != x"$recv" ] && exit 1
    :
  ) || rc=$?
  rm -rf $temp $keyfile $keyfile.pub
  [ $rc -gt 0 ] && atf_fail "ERROR proxycmd ssh test"
  :
}

xt_ssh_sshd_rproxied() {
  : =descr "ssh to revproxy sshd test using"

  local temp=$(mktemp -d) rc=0 keyfile=$(mktemp -p "$(get_user_ssh_dir)")
  (
    srv=$(randport)
    extport=$(randport)

    sshd_debug $srv $temp
    proxy="-S unix:$temp/ss$RANDOM -P 0"

    hoses $proxy proxy &
    proxypid=$!
    sleep 1

    hoses $proxy listen localhost $extport localhost $srv &
    fwdpid=$!

    canary=$RANDOM
    recv=$(ssh_debug -p $extport localhost echo $canary)

    qkill $sshpid $(getpids $proxypid) $(getpids $fwdpid)
    [ x"$canary" != x"$recv" ] && exit 1
    :
  ) || rc=$?
  rm -rf $temp $keyfile $keyfile.pub
  [ $rc -gt 0 ] && atf_fail "ERROR proxycmd ssh test"
  :
}



xatf_init
