#!python
"""
Implements enhanced socks5 protocol in python

"""
from ipaddress import ip_address, IPv4Address
from enum import IntEnum
import socket
from struct import pack, unpack
import os
import logging
from pyus import src

class S5CMD(IntEnum):
  '''Enumeration for SOCKS5 commands'''
  CONNECT = 1
  BIND = 2
  UDPASSOC = 3

class S5STATUS(IntEnum):
  '''Enumeration for SOCKS5 status responses'''
  OK = 0x00
  ERROR = 0x01
  DENIED = 0x02
  NETUNREACH = 0x03
  HOSTUNREACH = 0x04
  CONNREFUSED = 0x05
  TIMEOUT = 0x06
  PROTOERROR = 0x07
  BADADDR = 0x08

class ADDRTYPE(IntEnum):
  '''Enumeration for SOCKS5 address types'''
  IPv4 = 0x01
  DNS = 0x03
  IPv6 = 0x04
  UNIX = 0x80

class AUTH(IntEnum):
  '''SOCKS5 Authentication methods'''
  NONE = 0x00
  GSSAPI = 0x01
  BASIC = 0x02 # User/Password
  CHAP = 0x03
  CRAM = 0x05
  SSL = 0x06
  NDSAUTH= 0x07


PROTO_VER = 0x05
'''implemented SOSCKS protocol version'''
HELLO = bytes([PROTO_VER,0x01, 0x00])
'''Initialize SOCKS communications'''
WELCOME = bytes([PROTO_VER, 0x00])
'''Confirm the intialization of communications'''

BUFSIZE = 2048
'''Communications buffer size'''
TIMEOUT_SOCKET = 5
'''Time-out how much time we can spend in protocol transactions'''
DEFAULT_AF = socket.AF_INET
'''Default Address family either IPv4 or IPv6'''

def s5cmd_str(c):
  '''Returns a string represtantion of a SOCKS command code

  :param int c: command code
  :returns str: string version of the code
  '''
  cmd_str = [ None, 'Connect', 'Bind', 'UDPAssoc' ]
  if c < 1 or c >= len(cmd_str): return f'Unknown cmd ({c})'
  return cmd_str[c]

def s5status_str(s):
  '''Returns a string represtantion of a SOCKS status code

  :param int s: status code
  :returns str: string version of the status
  '''
  status_str = [
    'OK', 'General Error', 'Permission Denied', 'Network unreachable',
    'Host unreachable', 'Conection refused', 'Timed out', 'Protocol or Unsupported error',
    'Bad address'
  ]
  if s < 0 or s >= len(status_str): return f'Unknown status ({s})'
  return status_str[s]

def addrtype_str(a):
  '''Returns a string represtantion of a SOCKS address type

  :param int a: address type integer
  :returns str: string version of the address type
  '''
  atypes_str = [ None, 'IPv4', None, 'DNS', 'IPv6']
  if a == ADDRTYPE.UNIX: return 'unix'
  if a < 0 or a >= len(atypes_str) or atypes_str[a] is None:
    return f'Unknown Address ({a})'
  return atypes_str[a]

def auth_str(a):
  '''Returns a string represtantion of a SOCKS auth type

  :param int a: auth type code
  :returns str: string version of the auth type
  '''
  aa_str = [ None, 'GSSAPI', 'Basic', 'CHAP', None, 'CRAM', 'SSL', 'NDS Auth' ]
  if a < 0 or a >= len(aa_str) or aa_str[a] is None:
    return f'Unknown auth type ({a})'
  return aa_str[a]

def parse_addr(host: str):
  '''Identify and parse a host address

  :param str host: string containing address to parse
  :returns int,str: the address type code, and the parsed address
  '''
  try:
    addr = ip_address(host)
    if type(addr) is IPv4Address:
      return ADDRTYPE.IPv4, addr
    else:
      return ADDRTYPE.IPv6, addr
  except ValueError:
    ...
  if host.startswith('unix:'):
    return ADDRTYPE.UNIX, host[5:]
  else:
    return ADDRTYPE.DNS, host

def enc_addr(host):
  ''' Encode a SOCKS5 address

  :param str|tuple host: string containing an IPv4/IPv6/hostname to encode or a tuple from parse_addr
  :returns bytes: encoded byte string
  '''
  if isinstance(host,list) or isinstance(host,tuple):
    s5type, addr = host
  else:
    s5type, addr = parse_addr(host)
  if s5type == ADDRTYPE.IPv4 or s5type == ADDRTYPE.IPv6:
    return bytes(s5type) + addr.packed
  else:
    return bytes([s5type, len(addr.encode())]) + addr.encode()

def map_s5type(s5type,addr):
  '''Map s5type to AF
  :param int s5type: s5 address type code
  :param mixed addr: parsed address type
  :returns AF,str: Returns Adress family code, address to use in bind or connect functions
  '''
  if s5type == ADDRTYPE.IPv4:
    return socket.AF_INET, addr.compressed
  elif s5type == ADDRTYPE.IPv6:
    return socket.AF_INET6, addr.compressed
  elif s5type == ADDRTYPE.UNIX:
    return socket.AF_UNIX, addr
  elif s5type == ADDRTYPE.DNS:
    return DEFAULT_AF, addr
  else:
    raise ValueError

def enc_port(port):
  '''Encode a SOCKS5 port

  :param int port: port number
  :returns bytes: encoded port
  '''
  return bytes([(port>>8)&0xff,port&0xff])

def sendmsg(sock, msg, addr, port):
  ''' Send a socks5 message

  :param socket.socket sock: communications socket
  :param int msg: command or status code to send
  :param str addr: Address for the message as IPv4, IPv6 or DNS name
  :param int port: port for this message
  '''
  sock.sendall(bytes([PROTO_VER,msg, 0])+ enc_addr(addr) + enc_port(port))

def recvmsg(sock):
  ''' Read a SOCKS5 message

  :param socket.socket sock: communcations oscket
  :returns tuple[int,s5type, str,int]: message, s5type, address, port
  '''
  # +----+-----+-------+------+----------+----------+
  # |VER | MSG |  RSV  | ATYP | DST.ADDR | DST.PORT |
  # +----+-----+-------+------+----------+----------+
  s5req = sock.recv(4)
  if s5req[0] != PROTO_VER or s5req[2] != 0x00:
    raise ValueError

  msg = s5req[1]
  s5type = s5req[3]

  if s5type == ADDRTYPE.IPv4:
    addr = sock.recv(4)
    addr = ip_address(addr)
    addr = addr.compressed
  elif s5type == ADDRTYPE.IPv6:
    addr = sock.recv(16)
    addr = ip_address(addr)
    addr = addr.compressed
  elif s5type== ADDRTYPE.DNS:
    addr = sock.recv(1)
    addr = sock.recv(addr[0])
    addr = addr.decode()
  elif s5type == ADDRTYPE.UNIX:
    addr = sock.recv(1)
    addr = sock.recv(addr[0])
    addr = addr.decode()
  else:
    raise ValueError

  port = sock.recv(2)
  port, = unpack('!H',port)

  return msg, s5type, addr, port

def client_handshake(sock):
  '''Perform the client side of the handshake
  :param socket.socket sock: communications socket
  :returns bool: True on success, False on failure
  '''
  sock.sendall(HELLO)
  msg = sock.recv(BUFSIZE)

  return msg == WELCOME

def server_handshake(sock):
  '''Perform the server side of the handshake
  :param socket.socket sock: communications socket
  :returns bool: True on success, False on failure
  '''
  msg = sock.recv(BUFSIZE)
  if msg[0] != PROTO_VER or msg[1] < 1 or not AUTH.NONE in msg[2:]:
    return False
  sock.sendall(WELCOME)
  return True

def bind_port(addr, port):
  """
  Bind the socket to address and
  isten for connections made to the socket

  :param addr: address to bind to
  :param int port: port to listen to
  :returns socket.socket: Returns bound socket.

  When binding UNIX addresses, usually the port is ignored unless
  the socket path already exists, if that is the case if port == 0
  then the socket path will be removed.
  
  """
  if isinstance(addr,list) or isinstance(addr,tuple):
    s5type, addr = addr
  else:
    s5type, addr = parse_addr(addr)
  af, addr = map_s5type(s5type, addr)

  sock = socket.socket(af, socket.SOCK_STREAM)
  logging.info(f'Bind {addr}:{port} ({src()})')
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  if af == socket.AF_INET6:
    sock.bind((addr, port, 0, 0))
  elif af == socket.AF_UNIX:
    if port == 0 and os.path.exists(addr):
      os.remove(addr)
    sock.bind(addr)
  else:
    sock.bind((addr, port))
  sock.listen(10)
  return sock

def connect_to(dst_addr, dst_port):
  """ Connect to desired destination
  :param str dst_addr: destination address
  :param int dst_port: port
  :returns socket.socket: connected socket

  Creates a socket and proceeds to stablish a connection.
  """
  if isinstance(dst_addr,list) or isinstance(dst_addr,tuple):
    s5type, addr = dst_addr
  else:
    s5type, addr = parse_addr(dst_addr)
  af, addr = map_s5type(s5type, addr)

  sock = socket.socket(af, socket.SOCK_STREAM)

  sock.settimeout(TIMEOUT_SOCKET)
  if af == socket.AF_INET6:
    sock.connect((addr, dst_port, 0, 0))
  elif af == socket.AF_UNIX:
    sock.connect(addr)
  else:
    sock.connect((addr, dst_port))
  return sock
