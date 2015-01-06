#!/usr/bin/python

import socket
import sys
import threading
import time
import Constants


# Thread to serve clients
class ServerThread(threading.Thread):
  # constructor
  def __init__(self, server, address, connection):
    threading.Thread.__init__(self)
    self.server = server
    self.address = address
    self.connection = connection
    # whether the client has been logined
    self.login = False
    # number of failed login attempts
    self.failed_login_attempts = 0
    # the username of the client
    self.user = ''
    # time of the last operation
    self.last_op_time = time.time()

  # processes commands received from the client
  def run(self):
    try:
      while True:
        # receive message from the client
        msg = self.connection.recv(Constants.MAX_MSG_LENGTH)
        # If no message, break the loop
        if not msg:
          break
        # update the last operation time
        self.last_op_time = time.time()
        # if not logined,
        if not self.login:
          # process the login of the client
          self.process_login(msg)
        else:
          # process command
          if self.process_command(msg):
            # if the client exited, break the loop
            break
    except socket.error:
      pass
    # close the connection
    self.connection.close()

  # processes login command
  def process_login(self, msg):
    # if it is a login message ('login|username|password')
    if msg.startswith(Constants.MSG_LOGIN):
      # extract username and password
      cmd, user, password = msg.split('|')
      print 'login:', user, password
      # verify the username and password
      if self.server.verify_user(user, password):
        if not self.server.is_online(user):
          # if the user is not online
          # record his login time
          self.server.logins[user] = time.time()
          self.user = user
          self.login = True
          # send back a success message
          self.connection.send(Constants.MSG_SUCCESS)
          # send offline messages to him
          self.server.send_offline_messages(user, self.connection)
          # tell other clients
          self.server.broadcast('server', user + ' login', user)
        else:
          # if the user is already online, send back the message
          self.connection.send(Constants.MSG_USER_ALREADY_LOGINED)
      else:
        # increment the failed times
        self.failed_login_attempts += 1
        # if it exceeds the maximum retry times,
        if self.failed_login_attempts >= Constants.MAX_LOGIN_ATTEMPTS:
          # tell the client
          self.connection.send(Constants.MSG_LOGIN_EXCEED_MAX_TIMES)
          # block the ip
          self.server.block_client(self.address)
          # disconnect the client
          self.server.disconnect(self.address)
          return True
        else:
          # send back a failed message
          self.connection.send(Constants.MSG_FAILED)
    else:
      # send back a failed message
      self.connection.send(Constants.MSG_FAILED)
    return False

  # processes the command
  def process_command(self, msg):
    exited = False
    if msg == Constants.MSG_EXIT:
      # client exits
      exited = True
    elif msg == Constants.MSG_WHO_ELSE:
      # send back who else
      self.connection.send('[who else] ' + ', '.join(self.server.who_else(self.address)))
    elif msg == Constants.MSG_WHO_LAST_HOUR:
      # send back who logined in the last hour
      self.connection.send('[who last hour] ' + ', '.join(self.server.who_last_hour()))
    elif msg.startswith(Constants.MSG_BROADCAST):
      # extract the message
      cmd, msg = msg.split('|', 1)
      # broadcast the message
      self.server.broadcast(self.user, msg)
    elif msg.startswith(Constants.MSG_MESSAGE):
      # extract the target user and message
      cmd, user, msg = msg.split('|', 2)
      # send message to the target user
      if not self.server.message(self.user, user, msg):
        if user in self.server.passwords:
          self.connection.send(user + ' is offline now, and will see the message when login.')
        else:
          self.connection.send(user + ' doesn\'t exist.')
    elif msg == Constants.MSG_LOGOUT:
      # if the user want to logout, tell the other clients
      self.server.broadcast('server', self.user + ' logout')
      # disconnect
      self.server.disconnect(self.address)
      exited = True
    return exited


# Server class
class Server:
  # constructor
  def __init__(self, port):
    # server port
    self.port = port
    # {client address -> client threads}
    self.clients = {}
    # {username -> password}
    self.passwords = {}
    # {username -> last login time}
    self.logins = {}
    # {ip -> blocked time}
    self.blocked_ips = {}
    # {username -> [messages]}
    self.offline_messages = {}

  # starts the server
  def start(self):

    # load the password file, exit if failed.
    if not self.load_passwords():
      return

    # start a thread to check the timeout for inactive clients.
    t = threading.Thread(target=self.check_inactive_user)
    t.setDaemon(True)
    t.start()

    # create a server socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # force to reuse the address
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind the address
    s.bind(('127.0.0.1', self.port))
    # listen to at most 10 clients
    s.listen(10)

    try:
      # server loop
      while True:
        # wait for the connection of client
        connection, address = s.accept()
        # if a client connects, check its blocked time
        block_t = self.remaining_block_time(address)
        if block_t == 0:
          # if no blocked time left, send an accept message to it
          connection.send(Constants.MEG_ACCEPTED)
          # start a thread for it
          self.clients[address] = ServerThread(self, address, connection)
          self.clients[address].start()
        else:
          # if the client is blocked, send back its remaining blocked seconds.
          connection.send('|'.join([Constants.MSG_BLOCKED, str(block_t)]))
          # wait for acknowledge
          connection.recv(Constants.MAX_MSG_LENGTH)
          # close the connection
          connection.close()

    except KeyboardInterrupt:
      # press ctrl-c to stop the server.
      self.stop_server()

  # stop the server
  def stop_server(self):
    print 'Stop server...'
    # disconnect all the clients
    for address in self.clients.keys():
      self.disconnect(address)

  # disconnect a client
  def disconnect(self, address):
    # if the address is present,
    if address in self.clients:
      # get the client thread
      t = self.clients[address]
      if t.user != '':
        print 'logout:', t.user
      try:
        # send an exit message
        t.connection.send(Constants.MSG_EXIT)
        # close the connection
        t.connection.close()
      except socket.error:
        pass
      # remove its thread
      del self.clients[address]

  # returns the remaining blocked time of the client address
  def remaining_block_time(self, address):
    # get the ip from the address
    ip = address[0]
    # if it is not in the blocked dict, return 0
    if ip not in self.blocked_ips:
      return 0
    current_time = time.time()
    block_time = self.blocked_ips[ip]
    if current_time - block_time > Constants.BLOCK_TIME:
      # if the difference exceeds the block time, return 0
      return 0
    else:
      # otherwise return the remaining blocked time
      return Constants.BLOCK_TIME - (current_time - block_time)

  # blocks the ip of the client
  def block_client(self, address):
    # add the ip and blocked time to the blocked dict
    self.blocked_ips[address[0]] = time.time()

  # loads usernames and passwords from the password file
  # return True if success or False otherwise.
  def load_passwords(self):
    print 'load users'
    try:
      # open the file
      f = open(Constants.PASSWORD_FILE)
      # for each line in the file
      for line in f:
        # remove leading and trailing spaces
        line = line.strip()
        # if the line contains exactly one space
        if line.count(' ') == 1:
          # extract the username and password
          user, pwd = line.split(' ')
          # add them to the password dict
          self.passwords[user] = pwd
      # close the file
      f.close()
      return True
    except IOError:
      print '[Error] user_pass.txt is missing.'
      return False

  # returns True iff the username and password are correct.
  def verify_user(self, user, password):
    return user in self.passwords and self.passwords[user] == password

  # returns a list of online users excluding the current user
  def who_else(self, current_address):
    # create an empty list
    users = []
    # for each address of online clients
    for address in self.clients:
      # if it is not the address of the current client
      if address != current_address:
        # add its username to the list
        users.append(self.clients[address].user)
    return users

  # returns a list of users who logined in the last hour
  def who_last_hour(self):
    # get the current time
    current_time = time.time()
    # for each user logined, if its last login time is in the last hour,
    # add it to the list.
    return [user for user in self.logins
            if current_time - self.logins[user] <=
               Constants.SEC_PER_MIN * Constants.LAST_HOUR]

  # sends a message the a specified user.
  # returns True iff the user is online.
  def message(self, from_user, to_user, msg):
    found = False
    # add a message header
    msg = '[' + from_user + ']: ' + msg
    # for each online client
    for address in self.clients:
      t = self.clients[address]
      # if the target user is found, send the message to him.
      if t.user == to_user:
        t.connection.send(msg)
        found = True
    if not found:
      # if the user is not present, add the message to the offline messages
      if to_user not in self.offline_messages:
        self.offline_messages[to_user] = [msg]
      else:
        self.offline_messages[to_user].append(msg)
    return found

  # broadcasts the message to all the users
  def broadcast(self, from_user, msg, excluding_user=''):
    # add a message header
    msg = '[' + from_user + ' broadcast]: ' + msg
    # for each online client
    for address in self.clients:
      # send the message to it if it's not the excluding user.
      t = self.clients[address]
      if t.user != excluding_user:
        t.connection.send(msg)

  # returns True if the specified user is online
  def is_online(self, user):
    found = False
    # for each online client
    for address in self.clients:
      # if the username matches, return True
      if self.clients[address].user == user:
        found = True
        break
    return found

  # checks and removes inactive clients
  def check_inactive_user(self):
    # loop in background till the server ends
    while True:
      print 'check timeout for inactive users'
      # get the current time
      current_time = time.time()
      # for each online client
      for address in self.clients.keys():
        # if its last operation time is earlier than the timeout
        t = self.clients[address]
        if current_time - t.last_op_time > Constants.TIME_OUT * 60:
          # tell other clients
          self.broadcast('server', t.user + ' logout')
          print t.user, 'is kicked out'
          # automatically log him out
          self.disconnect(t.address)
      # sleep for a minute and check again
      time.sleep(Constants.SEC_PER_MIN)

  # send offline messages
  def send_offline_messages(self, user, connection):
    # if the user has offline messages
    if user in self.offline_messages:
      # send all the offline messages to him
      for msg in self.offline_messages[user]:
        connection.send('[offline message] ' + msg)
      # delete the messages
      del self.offline_messages[user]


if __name__ == '__main__':
  if len(sys.argv) == 2:
    try:
      # create a server
      port = int(sys.argv[1])
      s = Server(port)
      # start the server
      s.start()
    except ValueError:
      print '[Error] Invalid port'
  else:
    # invalid arguments
    print '[Error] Usage: python Server.py <port>'
