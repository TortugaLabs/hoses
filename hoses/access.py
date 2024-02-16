#python
'''
Access rules module

Access checks can use of the following variables:

- `host` : current host running the proxy
- Subject variables:
  - `subj` all compoments as a single string
  - `subj_commonName`
  - `subj_*` other subject components specified in the certificate
- Request variables:
  - `s5req_cmd` : SOCKS command as a string (`Connect`, `Bind`, `UDPAssoc`) 
  - `s5req_cmd_code` : Request command code
  - `s5req_addrtype` : SOCKS address type as a string (`IPv4`, `DNS`, `IPv6`, `unix`)
  - `s5req_addrtype_code` : SOCKS address type code
  - `s5req_address` : network address
  - `s5req_port : network port

For URLs, these can be referred using `{var}` substitutions.  For
external commands these are passed as environment variables.


```
allow|deny,hostname,subj,s5cmd_str,addrtype_str,address,port
```

'''
import platform
import os
import subprocess
import fnmatch
import requests

ACCESS_RULES = None
HOSTNAME = platform.node()
RULE_TARGETS = {
  'allow': True,
  'permit': True,
  'deny': False,
  'block': False,
}


def expand_vars(subj,s5req):
  '''Create a dictionary to be used in external components

  :param dict subj: identity of client
  :param dict s5req: Dictionary containing request parameters
  :returns dict: returns a flat dictionary with parameters
  '''
  vals = { 'host': HOSTNAME, 'subj': ''}
  for objpair in (('subj_',subj),('s5req_',s5req)):
    prefix,obj = objpair
    for key in obj:
      vals[prefix + key] = str(obj[key])  
  for key,val in sorted(subj.items()):
    vals['subj'] += f'/{key}={val}'
  return vals


def eval_rules(subj, s5req, rules):
  '''Evaluate rules

  :param dict subj: identity of client
  :param dict s5req: Dictionary containing request parameters
  :param str rules: Access rules specification
  :returns bool: returns True if access is allowed, False, if denied
  '''
  inp = None

  for ln in rules.lower().splitlines():
    ln = ln.strip()
    if ln.startswith(('#',';')) or ln == '': continue
    if ln in RULE_TARGETS: return RULE_TARGETS[ln]
    # OK, we need to evaluate rule
    parts = ln.split(',',1)
    if len(parts) != 2: continue # Incomplete rule
    op = parts[0].strip()
    if not op in RULE_TARGETS: # unrecognized rule
      continue
    if inp is None:
      inp = '{host},{subj},{s5req_cmd},{s5req_addrtype},{s5address},{s5port}'.format(**expand_vars(subj,s5req))
    if fnmatch.fnmatch(inp, parts[1]):
      return RULE_TARGETS[op]
  # No matches, is an implicit deny
  return False


def http_access_check(subj, s5req, rules):
  '''Read rules from a URL

  :param dict subj: identity of client
  :param dict s5req: Dictionary containing request parameters
  :param str rules: file containing rules
  :returns bool: returns True if access is allowed, False, if denied

  The URL can contain `{var}` that are substituted with the relevant
  variables.
  '''
  try:
    url = rules.format(**expand_vars(subj,s5req))
  except KeyError:
    # Malformed URL...
    return False
  
  r = requests.get(url)
  if r.status_code != 200: # Web server didn't like that request
    return False

  return eval_rules(subj,s5req,r.text)

def file_acccess_check(subj, s5req, rules):
  '''Read rules from a static file

  :param dict subj: identity of client
  :param dict s5req: Dictionary containing request parameters
  :param str rules: file containing rules
  :returns bool: returns True if access is allowed, False, if denied
  '''
  with open(rules,'r') as fp:
    text = fp.read()
  return eval_rules(subj, s5req, text)

def ext_access_check(subj, s5req, rules):
  '''Read rules from an external command

  :param dict subj: identity of client
  :param dict s5req: Dictionary containing request parameters
  :param str rules: executable generating rules
  :returns bool: returns True if access is allowed, False, if denied

  No command line arguments are passed to the external command. but environment
  variables are passed.

  Normally, the external command is a script.

  '''
  my_env = os.environ.copy()
  my_env.update(expand_vars(subj,s5req))

  rc = subprocess.run([rules],capture_output=True,text=True, env=my_env)
  if rc.returncode != 0: return False
  
  return eval_rules(subj,s5req,rc.stdout)

def check_access(subj,s5req):
  '''
  Check ACCESS_LIST configuration and evaluate for access permissions

  :param dict subj: Dictionary containing subject attributes
  :param dict s5req: Dictionary containing request parameters
  :returns bool: returns True if access is allowed, False, if denied
  '''
  if subj is None or ACCESS_RULES is None: return True # Allow everything by default

  if ACCESS_RULES.startswith('http://') or ACCESS_RULES.startswith('https://'):
    return http_access_check(subj,s5req,ACCESS_RULES)
  elif not os.path.exists(ACCESS_RULES):
    # Potential configuration error
    return False
  if os.access(ACCESS_RULES,os.X_OK):
    return ext_access_check(subj,s5req,ACCESS_RULES)
  else:
    return file_access_check(subj,s5req,ACCESS_RULES)


if __name__ == '__main__':
  print(HOSTNAME)
