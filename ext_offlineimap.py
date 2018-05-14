#!/usr/bin/python
import gnupg
import shlex
import getpass
import os

class Auth(object):
  def __init__(self, machine=None, port=None, login=None, password=None):
      self.__machine = machine
      self.__port = port
      self.__login = login
      self.__password = password

  def __str__(self):
      return 'Machine: %s\nPort: %s\nLogin: %s\nPassword: %s' % (self.__machine, self.__port, self.__login, self.__password)

  # Equality based on keys, i.e. not the password
  def __eq__(self, other):
      if type(other) is type(self):
          return (
            self.__machine == other.__machine and
            self.__port == other.__port and
            self.__login == other.__login )
      return False

  def __ne__(self, other):
      return not self == other

  def password(self):
      return self.__password

# As offlineimap is multithreaded, you want to get the gpg
# password only once at extension import time
getPasswordOnce=getpass.getpass()

# Hint:
# remotepasseval = get_password('imap.mail.com', '993', 'user@foo.com')
def get_password(machine=None, port=None, login=None, authinfo='~/.authinfo.gpg'):
    auth = Auth(machine, port, login)
    data = gnupg.GPG().decrypt_file(
        open(os.path.expanduser(authinfo),'rb'),
        passphrase=getPasswordOnce)

    # Decrypt failed
    if (not data.ok):
        raise ValueError('decryption of authinfo failed')

    for auth_row in str(data).splitlines():
        # shlex handles quoted values
        it_auth_vals = iter(shlex.split(auth_row))
        auth_dict = {}
        # Clever use of iterator to get adjacent values
        for (moniker,value) in zip(it_auth_vals, it_auth_vals):
            auth_dict[moniker] = value
        auth_row_obj = Auth(**auth_dict)
        if (auth_row_obj == auth):
            return auth_row_obj.password()

    # No matches return None
    raise LookupError('no matching authinfo entry found')
