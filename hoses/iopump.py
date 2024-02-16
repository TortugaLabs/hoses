#python3

import socket
from enum import IntEnum
import os
import sys
import select
import errno

class IOHelper:
  ''' Base helper class

  Is meant to help handling sockets vs. stdin/stdout channels

  Tracks the shutdown status
  '''
  OPEN = 0x00
  WR = 0x01
  RD = 0x02
  CLOSED = 0x03
  BUFSIZE = 2048

  def __init__(self):
    '''constructor'''
    self.status = IOHelper.OPEN
  def shutdown(self, s: int):
    ''' Shutdowns only one side of the connection '''
    self.status |= s
  def not_closed(self):
    '''Check if the connection is not fully closed'''
    return self.status != IOHelper.CLOSED
  def is_readable(self):
    '''Check if this connection can be read

    It does it by checking the status property.

    It is also used to poll the write side of the connection
    to make sure that the peer has not closed things yet.
    '''
    # we do this to properly detect socket tear downs
    res = self.status & IOHelper.RD != IOHelper.RD
    if not res and self.status & IOHelper.WR != IOHelper.WR:
      # Check if the writing side is still up...
      try:
        self.send(b'')
      except BrokenPipeError:
        self.status |= IOHelper.WR
    return res

  def pump(self, out):
    '''Main pump function'''
    data = self.recv(IOHelper.BUFSIZE)
    if data == b'':
      self.shutdown(IOHelper.RD)
      out.shutdown(IOHelper.WR)
    else:
      out.send(data)

class SockHelper(IOHelper):
  '''Helper for socket connections'''
  def __init__(self, sock: socket.socket):
    ''' Constructor 
    :param socket.socket sock: socket to initialize
    '''
    super().__init__()
    self.sock = sock
    sock.settimeout(None)
  def reader(self) -> socket.socket:
    ''' Returns object that can be used by `select` to poll for input
    :returns stream: stream object to select for readers
    '''
    return self.sock
  def recv(self, sz: int) -> bytes:
    ''' Receive network data 
    :param int sz: byte count to read
    :returns bytes: read data    
    '''
    try:
      return self.sock.recv(sz)
    except ConnectionResetError:
      return b''
  def send(self, data: bytes) -> None:
    '''Send network data
    :param bytes data: data to send
    '''
    self.sock.sendall(data)
  def shutdown(self, s: int) -> None:
    '''Shutdown a connection
    :param int s: how to shutdown connection, use IOHelper.RD or IOHelper.WR

    Will close for reading if s is IOHelper.RD or for writing if s is 
    IOHelper.WR.  
    '''
    super().shutdown(s)
    if s & IOHelper.RD == IOHelper.RD:
      try:
        self.sock.shutdown(socket.SHUT_RD)
      except OSError as e:
        if e.errno != errno.ENOTCONN: raise
    if s & IOHelper.WR == IOHelper.WR: self.sock.shutdown(socket.SHUT_WR)
  def close(self):
    '''Close connection'''
    if self.status & IOHelper.RD != IOHelper.RD: self.sock.shutdown(socket.SHUT_RD)
    if self.status & IOHelper.WR != IOHelper.WR: self.sock.shutdown(socket.SHUT_WR)
    self.sock.close()

class PipeHelper(IOHelper):
  '''Helper for stdin/stdout connections'''
  def __init__(self, ior, iow):
    '''Pipe helper constructor

    :param stream ior: stdin stream
    :param stream iow: stdout stream
    '''
    super().__init__()
    self.inp = os.fdopen(ior.fileno(),'r+b',0) # Remove buffering ...
    self.out = os.fdopen(iow.fileno(),'w+b',0) # ... and switch to binary
  def reader(self):
    ''' Returns object that can be used by `select` to poll for input
    :returns stream: stream object to select for readers
    '''
    return self.inp
  def recv(self,sz: int) -> bytes:
    ''' Receive pipe data 
    :param int sz: byte count to read
    :returns bytes: read data    
    '''
    x = self.inp.read(sz)
    return x
    # ~ return self.inp.read(sz)
  def send(self,data: bytes) -> None:
    '''Send pipe data
    :param bytes data: data to send
    '''
    self.out.write(data)
  def shutdown(self, s: int):
    '''Shutdown a connection
    :param int s: how to shutdown connection, use IOHelper.RD or IOHelper.WR

    Will close for reading if s is IOHelper.RD or for writing if s is 
    IOHelper.WR.  
    '''
    super().shutdown(s)
    if s & IOHelper.WR == IOHelper.WR: self.out.close()
    if s & IOHelper.RD == IOHelper.RD: self.inp.close()
  def close(self):
    '''Close connection'''
    if self.status & IOHelper.RD != IOHelper.RD: self.inp.close()
    if self.status & IOHelper.WR != IOHelper.WR: self.out.close()

def add_iohelper(io):
  '''Wrap IO channels with a helper

  :param io: I/O channel to wrap
  :returns: IO helper class
  '''

  if isinstance(io,IOHelper):
    # No need to do anything
    return io    
  elif isinstance(io, socket.socket):
    return SockHelper(io)
  elif isinstance(io, list) or isinstance(io, tuple):
    return PipeHelper(io[0],io[1])
  else:
    raise TypeError


def pump(ioa,iob) -> None:
  '''Pump data between to IO channels

  :param PipeHelper|SockHelper ioa: helper object for a socket or stdin/out
  :param PipeHelper|SockHelper iob: helper object for a socket or stdin/out
  '''
  ioa = add_iohelper(ioa)
  iob = add_iohelper(iob)

  while ioa.not_closed() and iob.not_closed():
    selector = []
    if ioa.is_readable(): selector.append(ioa.reader())
    if iob.is_readable(): selector.append(iob.reader())

    readers, _, _ = select.select(selector, [], [], None if len(selector) > 1 else 0.1)

    if not readers: return

    if ioa.reader() in readers: ioa.pump(iob)
    if iob.reader() in readers: iob.pump(ioa)

  ioa.close()
  iob.close()

if __name__ == '__main__':
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect(('localhost', 8090))

  pump(sock, (sys.stdin,sys.stdout))

