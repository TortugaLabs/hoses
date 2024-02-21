#!python
try:
  from icecream import ic
  ic.configureOutput(includeContext=True)
except ImportError:  # Graceful fallback if IceCream isn't installed.
  ic = lambda *a: None if not a else (a[0] if len(a) == 1 else a)  # noqa

import errno
import json
import logging
import os
import select
import socket
import ssl
import sys
import time
from threading import Thread, active_count

import access
import iopump
import socks5x as s5x
import sslctx
import unixcreds
from pyus import src


AUDIT_LOG = None

def audit_log(event, **kwargs):
  '''Add event to the audit log
  :param str event: eventy to log
  :param dict kwargs: keywords

  - src : (file,line) tupple

  - peer : dict
  - subj : dict|None

  - error : Exception or simple string
  - s5req : dict
  - status : str
  - client : connection from bind request
  '''
  if AUDIT_LOG is None: return
  ic(event,kwargs)
  with open(AUDIT_LOG,'a') as fp:
    fp.write(':'.join([time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime()),
                      event,
                      json.dumps(kwargs)
                      ]) + '\n')

def getpeer_ex(peer,sock):
  '''Convert peer tuple into dict.  Enhances UNIX creds

  :param tuple peer: peer from accept or getpeer functions
  :param socket.socket sock: connected socket to get peer info
  :returns dict: with the extended peer info
  '''
  if peer:
    match len(peer):
      case 2:
        return {'type': 'IPv4', 'addr': peer[0], 'port': peer[1] }
      case 4:
        return {'type': 'IPv6', 'addr': peer[0], 'port': peer[1], 'extra': [peer[2],peer[3]] }
      case other:
        return { 'type': 'Unknown', 'addr': str(client) }
  else:
    # Assume it is a UNIX socket
    peer = unixcreds.unixcreds(sock)
    peer['type'] = 'UNIX'
    return peer



def serve_client(sock, peer):
  '''Serve a SOCKS proxy client connection

  :param socket.socket sock: socket of proxy client
  :param dict peer: peer information

  Will perform SOCKS protocol functionality.
  '''
  sock.settimeout(s5x.TIMEOUT_SOCKET)

  if not s5x.server_handshake(sock):
    logging.error(f'Handshake error {src()}')
    audit_log('Error', src = src(),peer=peer,error='Handshake error')
    sock.close()
    return

  cmd, addr, port = s5x.recvmsg(sock)
  if cmd == s5x.S5STATUS.EOF:
    logging.error(f'Communications Interruption {src()}')
    audit_log('Error',src=src(),peer=peer,error='Protocol error')
    sock.close()
    return

  s5req = {
    'cmd': s5x.s5cmd_str(cmd),
    'cmd_code': cmd,
    'addrtype': addr.addrtype_str(),
    'addrtype_code': addr.type,
    'address': addr.addr_str(),
    'port': port,
  }
  ic(s5req)
  subj = None
  if isinstance(sock,ssl.SSLSocket):
    peercert = sock.getpeercert()
    if not peercert is None and 'subject' in peercert:
      subj = sslctx.flatten_dn(peercert['subject'])
      ic(sslctx.strfy(subj))
  ic(subj)

  # Check access rules...
  # ~ if not access.ACCESS_RULES is None:
  if not access.check_access(peer, subj, s5req):
    s5x.sendmsg(sock, s5x.S5STATUS.DENIED, (s5type,addr), port)
    logging.error(f'Access denied: {peer}, {subj}, {s5req} on {src()}')
    audit_log('Forbidden',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.DENIED))

    sock.close()
    return

  if cmd == s5x.S5CMD.CONNECT:
    logging.info(f'connect_to {addr}:{port} {src()}')
    try:
      target = s5x.connect_to(addr,port)
    except OSError as e:
      if e.errno == errno.ENETUNREACH:
        code = s5x.S5STATUS.NETUNREACH
      elif e.errno == errno.EHOSTUNREACH:
        code = s5x.S5STATUS.HOSTUNREACH
      elif e.errno == errno.ECONNREFUSED:
        code = s5x.S5STATUS.CONNREFUSED
      elif e.errno == errno.ETIMEDOUT:
        code = s5x.S5STATUS.TIMEOUT
      else:
        code = s5x.S5STATUS.ERROR

      s5x.sendmsg(sock, code, addr, port)
      logging.error(f'Connect error:{e} {peer} {subj} {s5req} on {src()}')
      audit_log('S5error',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(code), error=e)

      sock.close()
      return
    s5x.sendmsg(sock, s5x.S5STATUS.OK, addr, port)
    audit_log('Connect',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.OK))
    iopump.pump(sock, target)
    logging.info(f'Disconnected {peer} {subj} {src()})')
    audit_log('Disconnect',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.OK))
  elif cmd == s5x.S5CMD.BIND:
    try:
      listener = s5x.bind_port(addr,port)
    except OSError as e:
      if e.errno == errno.EADDRINUSE:
        code = s5x.S5STATUS.BADADDR
      else:
        code = s5x.S5STATUS.ERROR

      s5x.sendmsg(sock, code, addr, port)
      logging.error(f'Unhandled error {e} {src()}')
      audit_log('S5ERROR',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(code), error=e)
      sock.close()
      return

    audit_log('Bind',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.OK))

    while True:
      readers, _, _ = select.select([sock, listener], [], [], None)
      if sock in readers:
        # If we receive anything at this point, it is an error
        # so we close connection
        logging.debug(f'Listener client gone {src()}')
        audit_log('Error',src=src(),peer=peer,subj=subj,s5req=s5req,error='Bound client gone')

        listener.close()
        sock.close()
        return
      if listener in readers:
        newclient, iinfo = listener.accept()
        break

    listener.close()

    ic(addr,port,iinfo)
    logging.debug(f'{iinfo} {src()}')
    inclient = getpeer_ex(iinfo, newclient)

    # ~ if iinfo:
      # ~ s5addr, s5port = (s5x.SocksAddress(iinfo[0]),iinfo[1])
    # ~ else:
      # ~ s5addr = addr
      # ~ s5port = port
    # ~ s5x.sendmsg(sock, s5x.S5STATUS.OK, s5addr, s5port)
    s5x.sendmsg(sock, s5x.S5STATUS.OK, addr, port)

    audit_log('Bind-Accept',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.OK),client=inclient)

    iopump.pump(sock, newclient)
    logging.info(f'Disconnected {src()})')
    audit_log('Bind-Closed',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.OK),client=inclient)
  elif cmd == s5x.S5CMD.UDPASSOC:
    s5x.sendmsg(sock, s5x.S5STATUS.PROTOERROR, addr, port)
    logging.error(f'Request unipmeneted UDPASSOCIATE {src()}')
    audit_log('S5ERROR',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.PROTOERROR), error='Unimplemented UDPASSOCIATE')
    sock.close()
  else:
    s5x.sendmsg(sock, s5x.S5STATUS.PROTOERROR, addr, port)
    logging.error(f'Request unknown command {src()}')
    audit_log('S5ERROR',src=src(),peer=peer,subj=subj,s5req=s5req,status=s5x.s5status_str(s5x.S5STATUS.PROTOERROR), error='Unknown request')
    sock.close()

def proxy(sockss_server, sockss_port, cert,key, ca):
  """ Main function
  :param str sockss_server: SOCKS proxy server address
  :param int sockss_port: SOCKS proxy server port
  :param str cert|None: file path to certificate
  :param str key|None: file path to certificate's key
  :param str ca|None: file path to CA certificate

  This function implements the SOCKS proxy functionality.

  """

  context = sslctx.server_context(cert, key, ca)
  listener = s5x.bind_port(sockss_server, sockss_port)
  audit_log('Started',pid=os.getpid(),src=src(),cmdline=sys.argv)

  while True:
    io, peer = listener.accept()
    peer = getpeer_ex(peer,io)

    if not context is None:
      try:
        io = context.wrap_socket(io, server_side=True)
      except ssl.SSLError as e:
        audit_log('Error',src=src(),error=str(e),peer=peer)
        logging.error(f'SSLError:{e} from {peer} on {src()}')
        io.close()
        continue

    logging.info(f'Client: {peer} connected')
    recv_thread = Thread(target=serve_client, args=(io, peer))
    recv_thread.start()
