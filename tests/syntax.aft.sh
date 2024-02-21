#!/usr/bin/atf-sh

[ -n "${IN_COMMON:-}" ] && return
type atf_get_srcdir >/dev/null 2>&1 || atf_get_srcdir() { pwd; }
. $(atf_get_srcdir)/testlib/common.sh


xt_syntax() {
  : =descr Do a simple syntax check
  local cnt=0

  find $SRC_DIR -name '*.py' | (while read f
  do
    python3 -m py_compile "$f" || cnt=$(($cnt + 1))
  done ; exit $cnt) || cnt=$?
  if [ $cnt -gt 0 ] ; then
    atf_fail "Files failed to compile: $cnt"
  fi
  :
}

xatf_init
