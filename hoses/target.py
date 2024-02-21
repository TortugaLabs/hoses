#!python
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import subprocess
import shlex
import socket
import sys
import logging
# from threading import Thread, active_count

import iopump
import pyus
import socks5x as s5x
from pyus import src

def serve_target(peer, dest = [], background = False, cmd = False, wrapper = None):
  '''Connect a network socket to a target

  :param socket.socket peer: peer connection
  :param list dest: destination target
  :param bool background: process should go to the background upon connect
  :param bool cmd: destination target is a command
  :param closure wrapper|None: wrapper function (used for creating SSL sockets)

  Create a IO channel to the target and starts communicating with it.

  '''
  if len(dest) == 0:
    iopump.pump(peer, (sys.stdin.buffer,sys.stdout.buffer))
    return

  if background:
    pyus.daemonize()
    pyus.null_io(True, keep_stderr = True)

  if cmd:
    if len(dest) == 1:
      command = dest[0]
      if len(shlex.split(command)) > 0: shell = True
    else:
      command = dest
      shell = False
    proc = subprocess.Popen(command, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    logging.debug(f'{proc} {src()}')
    iopump.pump(peer, (proc.stdout,proc.stdin))
    return

  addr = s5x.SocksAddress(dest[0])
  if addr.type == s5x.SocksAddress.UNIX:
    sock = s5x.connect_to(addr,0)
  elif len(dest) != 2:
    logging.error('Must specify {host} {port} values')
    return
  else:
    sock = s5x.connect_to(addr, int(dest[1]))
  if not wrapper is None: sock = wrapper(sock, dest[0])

  iopump.pump(peer, sock)
