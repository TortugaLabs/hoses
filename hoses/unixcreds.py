#!python
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import socket
import struct
import pwd,grp
import os
import pyus

SO_PEERCRED = 17
'''Pulled from /usr/include/asm-generic/socket.h'''


def unixcreds(sock):
  '''Get credentials from a UNIX socket

  :param socket.socket sock: socket to get peer info
  :returns dict: containing socket credentials
  '''
  creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize('3i'))
  pid, uid, gid = struct.unpack('3i',creds)

  res = {
    'pid': pid,
    'uid': uid,
    'gid': gid,
    'user': pwd.getpwuid(uid).pw_name,
    'group': grp.getgrgid(gid).gr_name,
    'exe': os.readlink(f'/proc/{pid}/exe'),
    'comm': pyus.readfile(f'/proc/{pid}/comm').strip(),
    'cmdline': pyus.readfile(f'/proc/{pid}/cmdline').rstrip('\x00').split('\x00'),
  }

  # environ?, comm
  #
  # ~ ic('pid: %d, uid: %d, gid %d' % (pid, uid, gid))
  return res

def strfy(creds, item=None):
  '''Convert the credentials dict or its components into a single string

  :param dict dn: creds dictionary
  :param str item|None: If not None, a single item to convert to string
  '''
  if item is None:
    tx = ''
    q=''
    for k,v in sorted(creds.items()):
      tx += f'{q}{k}='
      q=';'
      if isinstance(v,list):
        tx += ':'.join([s.replace(':',',').replace(';',',') for s in v])
      else:
        tx += v.replace(';',',') if isinstance(v,str) else str(v)
    return tx

  if not item in creds: return ''
  if isinstance(creds[item],list):
    return ':'.join([s.replace(':',',').replace(';',',') for s in creds[item]])
  else:
    return creds[item].replace(';',',') if isinstance(creds[item],str) else str(creds[item])


if __name__ == '__main__':
  a,b = socket.socketpair(socket.AF_UNIX)

  ic(a.getpeername())

  ca = ic(unixcreds(a))
  cb = ic(unixcreds(b))
  ic(strfy(ca))
  ic(strfy(cb,'cmdline'))
  ic(strfy(cb,'cmdline'))
  ic(strfy(cb,'uid'))

