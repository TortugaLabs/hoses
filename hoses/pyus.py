#!python3
###$_begin-include: mypylib/pyus.in.py
#python
import sys
import os
from inspect import getframeinfo, stack

'''
Miscellaneous python utilities
'''

#python
#import sys
#import os

def daemonize():
  '''Makes the current process run in the background.

  Internally, it forks a couple of times to make sure that the process
  is properly placed in the background and independant of the calling
  process.
  '''
  newpid = os.fork()
  if newpid != 0: sys.exit(0)
  os.setsid()
  newpid = os.fork()
  if newpid != 0: sys.exit(0)

#python
#import sys
#import os

def file_args(args):
  """Read arguments from files

  :param list args: arguments to process
  :returns list: replacement args

  Arguments that beging with '@' are replaced with the contents
  of an argument file.  Unless the file does not exists and
  then the argument is just added as is.

  Argument file syntax:

  - Empty lines and lines staring with '#' or ';' are ignored.
  - Lines are automatically pre-pended with '--' so as to pass
    them as extended flag variables.
  - Lines that begin with "'" are treated as verbatim, i.e.
    the '--' is not added.
  - Lines that begin with three single quotes "'''" are treated as
    heredocs, so from the on input is read until a line
    with "'''" is found.  The whole input until then is added
    as a single argument.

  """

  newargs = []
  for i in args:
    if i.startswith('@'):
      if not os.path.isfile(i[1:]):
        newargs.append(i)
        continue
      with open(i[1:],'r') as fp:
        in_heredoc = False
        for ln in fp:
          if in_heredoc:
            if ln.strip() == "'''":
              in_heredoc =  False
              newargs[-1] = newargs[-1].rstrip()
              continue
            newargs[-1] += ln
          else:
            ln = ln.strip()
            if ln.startswith(('#',';')) or ln == '': continue # comments
            if ln.startswith("'''"):
              in_heredoc = True
              ln = ln[3:]
              if ln != '': ln += '\n'
            elif ln.startswith("'"):
              ln = ln[1:]
              if ln.endswith("'"): ln = ln[:-1]
            else:
              ln = '--' + ln
            newargs.append(ln)
    else:
      newargs.append(i)
  return newargs

#python3
#from inspect import getframeinfo, stack

def myself():
  '''Return information of the caller

  :returns object: with attributes

  Among the attributes returned:

  - filename
  - lineno
  - function
  - code_context : list of lines being executed.
  '''
  caller = getframeinfo(stack()[1][0])
  return caller

#python
#import sys
#import os

saved_fds = []
'''Used internally to save fds by null_io'''

def null_io(close = False, keep_stderr = False):
  '''Redirects I/O to `/dev/null`

  :param bool close: Defaults to False, if True, the current I/O channels are closed

  It will manipulate the operating sytems file descriptors and redirect them
  to /dev/null.  By default, it will save the existing file descriptors so
  that they can be restored later with `denull_io`.

  If `False` was passed as the `close` parameter, then previous file descriptors
  will be closed and `denull_io` will not work anymore.

  '''
  if close:
    if len(saved_fds) == 0:
      null_fd = os.open(os.devnull,os.O_RDWR)
      os.dup2(null_fd, 0)
      os.dup2(null_fd, 1)
      if not keep_stderr: os.dup2(null_fd, 2)
      os.close(null_fd)
    else:
      saved_fds[0].close()
      saved_fds[1].close()
      if not saved_fds[2] is None: saved_fds[2].close()
      saved_fds[3].close()
    return

  if len(saved_fds) == 0:
    null_fd = os.open(os.devnull,os.O_RDWR)
    saved_fds.append(os.dup(0))
    saved_fds.append(os.dup(1))
    saved_fds.append(None if keep_stderr else os.dup(2))
    saved_fds.append(null_fd)
    saved_fds.append(0)
  else:
    null_fd = saved_fds[3]

  if saved_fds[4]:
    # Already Nulled
    saved_fds[4] += 1
    return

  saved_fds[4] += 1
  os.dup2(null_fd, 0)
  os.dup2(null_fd, 1)
  if not keep_stderr: os.dup2(null_fd, 2)

def denull_io():
  '''Restores `null_io` redirections.
  '''
  saved_fds[4] -= 1
  if saved_fds[4]: return

  os.dup2(saved_fds[0], 0)
  os.dup2(saved_fds[1], 1)
  if not saved_fds[2] is None: os.dup2(saved_fds[2], 2)

#python
import os

# child reaper
def reap_child_proc(signum, frame):
  '''Reaps child processes

  :param int signum: signal being processed
  :param frame frame: execution frame

  It simply reaps child process as they finish.

  Usage:

  ```python
  import signal

  signal(signal.SIGCHLD, reap_child_proc)

  ```
  '''
  while True:
    try:
      pid, status = os.waitpid(-1, os.WNOHANG)
    except OSError:
      return

    if pid == 0:  # no more zombies
      return

#python3
#from inspect import getframeinfo, stack

def src():
  '''Return file,line of caller

  :returns (str,int): file and line of caller
  '''
  caller = getframeinfo(stack()[1][0])
  return (caller.filename,caller.lineno)

#python
# import sys

class Unbuffered(object):
  '''Wraps a stream object so that all its output gets flushed right away
     Unbuffered I/O

     A lot of times, daemons will run in the background with output
     going to a file or to a pipe

     This makes sure that the output is handled immediatly
  '''
  def __init__(self, stream):
    '''Create stream
    :param stream: stream to be wrapped.
    '''
    self.stream = stream
  def write(self, data):
    '''Auto flush writes
    :param bytes|str data: data to output
    '''
    self.stream.write(data)
    self.stream.flush()
  def writelines(self, datas):
    '''Auto flush writelines
    :param bytes|str datas: datas to output
    '''
    self.stream.writelines(datas)
    self.stream.flush()
  def __getattr__(self, attr):
    '''internal function to make the stream transparent'''
    return getattr(self.stream, attr)

def unbuffered_io():
  '''Makes stdout and stderr unbuffered streams

  sys.stdout and sys.stderr is modified.  Note that the underlying
  OS objects are unchanged.
  '''
  sys.stdout = Unbuffered(sys.stdout)
  sys.stderr = Unbuffered(sys.stderr)

#!python3

def readfile(name):
  '''Read the contents of a file as whole

  :param str name: File name to read
  :returns str: contents of file
  '''
  with open(name,'r') as fp:
    text = fp.read()
  return text


###$_end-include: mypylib/pyus.in.py
