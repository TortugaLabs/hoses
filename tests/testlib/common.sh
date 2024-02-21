#!/bin/sh
[ -n "${IN_COMMON:-}" ] && return
IN_COMMON=true

. $(atf_get_srcdir)/testlib/xatf.sh
REPO_DIR=$(dirname $(readlink -f $(atf_get_srcdir)))
SRC_DIR=$REPO_DIR/hoses

in_kyua() {
  xargs -0 echo < /proc/$PPID/cmdline | grep -q kyua
}

getspids() {
  local ppid="$1"
  local r=$(ps -e -o pid=,ppid= | awk -vsrv=$ppid '$2 == srv { print $1 }')
  for i in $r
  do
    getspids $i
  done
  echo $r
}

getpids() {
  echo -n "$1 "
  getspids "$1" | xargs
}

hoses() {
  python3 $SRC_DIR/__main__.py "$@"
}

randtext() {
  [ $# -eq 0 ] && set - 200

  if type fortune >/dev/null 2>&1 ; then
    for i in $(seq 1 $1)
    do
      fortune
    done
  else
    for i in $(seq 1 $1)
    do
      for j in $(seq $((100 + ($RANDOM % 200))))
      do
	j=$(printf '%02x' $((($RANDOM % 64)+32)))
	printf "\\x$j"
      done
    done
  fi
  echo bye
}

randport() {
  local port=$RANDOM
  while [ $port -lt 2048 ]
  do
    port=$RANDOM
  done
  echo $port
}

qkill() {
  echo "Killing $*"
  for pid in "$@" ; do
    [ -d /proc/$pid ] && kill $pid || :
  done
}

get_user_ssh_dir() {
  echo $(getent passwd $(id -un) | cut -d: -f6)/.ssh
}


sshd_debug() {
  sshport="$1"
  local t="$2" k keys='' authkeys
  mkdir -p "$t/etc/ssh"
  ssh-keygen -A -f $t
  yes | ssh-keygen -q -t rsa -f $keyfile -N '' -C 'test user key' ; echo yes
  keys=$(find $t/etc/ssh -type f -name '*_key' | sed -e 's/^/-h /' | xargs)
  authkeys="-o AuthorizedKeysFile=$keyfile.pub"
  $(which sshd) -D -p $sshport -f /dev/null $keys $authkeys &
  sshpid=$!
  sleep 1
}

ssh_debug() {
    ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
        -i $keyfile -p $sshport "$@"
}

fixunixcn() {
  case "$1" in
  unix:*)
    echo unix:$(basename "${1#unix:}")
    ;;
  *)
    echo "$*"
    ;;
  esac
}

newcert() {
  openssl req -new \
	-newkey rsa:2048 \
	-subj "$1" \
	-days 365 \
	-nodes -x509 \
	-keyout $2.key \
	-out $2.crt
}
