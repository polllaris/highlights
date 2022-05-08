# Python 3.7+
# This is not a compliant socks5 implementation
# as it does not currently support GSSAPI.
# SEE: https://datatracker.ietf.org/doc/html/rfc1928#section-4
#
# Author: Polllaris

import io
import re
import json
import time
import socket
import logging
import traceback
import struct
from struct import pack
from struct import unpack
from select import select
from socket import AF_INET
from socket import SOCK_STREAM
from socket import SOL_SOCKET
from socket import SO_REUSEADDR
from socket import inet_aton
from socket import inet_ntoa
from socket import MSG_PEEK
from threading import Thread
from typing import Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field, asdict

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("socks")

class AuthenticationError(Exception):
	""" authentication failure """
class RoutingError(Exception):
	""" an error related to routing """
class BlacklistingError(RoutingError):
	""" something was blacklisted """
class OverrideError(RoutingError):
	""" no override was set for that host """
class SocksError(Exception):
	""" an exception relating to socks """
class SocksMethodError(SocksError):
	""" an exception relating to method selection """
class SocksCommandError(SocksError):
	""" an exception relating to the command requested """
class SocksAddressError(SocksError):
	""" an exception relating to the provided address or address type """
class SocksBindError(SocksError):
	""" an exception that occurs when binding/multiplexing binding fails """
class SocksAuthenticationError(SocksError):
	""" an error with authentication happened such as invalid username/password """

@dataclass
class Account:

	username:str
	password:str
	role:str = "default"
	ports:list[int] = field(default_factory=list)

@dataclass
class Route:

	"""
	Represents where a connection should be made to

	@ivar dst_addr the destination IPv4
	@ivar dst_port the destination port
	@ivar dst_host the destination hostname
	"""

	dst_addr:str
	dst_port:int
	dst_host:Optional[str] = None

@dataclass
class ListingRule:

	type:str
	match:str
	host:Optional[str] = None
	mask:Optional[str] = None
	users:list[str] = field(default_factory=list)
	roles:list[str] = field(default_factory=list)
	ports:list[int] = field(default_factory=list)

	@classmethod
	def make_from_dict(cls, rule:dict) -> "ListingRule":

		match = rule.get("match")
		schema = rule.get("match")
		parsed = urlparse(schema)

		type = parsed.scheme
		host = parsed.netloc

		try:
			n = int(parsed.path.split("/")[1]) // 8
			nmask = ".".join(host.split(".")[0:n])
		except Exception as e:
			nmask = None

		users = rule.get("users", [])
		roles = rule.get("roles", [])
		ports = rule.get("ports", [])

		instance = cls(
			type=type,
			match=match,
			host=host,
			mask=nmask,
			users=users,
			roles=roles,
			ports=ports
		)

		return instance

	def matches(self, route:Route, account:Account) -> bool:

		""" check if the host, port, user and role match this listing rule """

		host = route.dst_host or route.dst_addr
		port = route.dst_port
		user = account.username
		role = account.role

		host_match = host == self.host
		mask_match = host.startswith(self.mask) if self.mask else False
		port_match = port in self.ports if self.ports else True
		user_match = user in self.users if self.users else True
		role_match = role in self.roles if self.roles else True

		if self.type == "host" or self.type == "addr":
			return host_match and port_match and user_match and role_match
		else:
			return port_match and user_match and role_match and mask_match

@dataclass
class OverrideRule:

	host:str
	override:str
	ports:dict[int, int]
	users:list[str] = field(default_factory=list)
	roles:list[str] = field(default_factory=list)

	@classmethod
	def make_from_dict(cls, rule:dict) -> "OverrideRule":

		host = rule.get("host")
		override = rule.get("override")
		# json doesn't allow integers as dictionary keys, need to convert them back
		ports = rule.get("ports", {})
		for key, value in ports.copy().items():
			del ports[key]
			ports[int(key)] = value

		users = rule.get("users", [])
		roles = rule.get("roles", [])

		return cls(host, override, ports, users, roles)

	def matches(self, route:Route, account:Account) -> bool:

		host = route.dst_host or route.dst_port
		user = account.username
		role = account.role

		host_match = host == self.host
		user_match = user in self.users if self.users else True
		role_match = role in self.roles if self.roles else True

		return host_match and user_match and role_match

@dataclass
class RouterState:

	mode:str
	accounts:list[Account]
	blacklist:list[ListingRule]
	whitelist:list[ListingRule]
	overrides:list[dict]

	@classmethod
	def make_from_dict(cls, config:dict) -> "RouterState":

		mode = config.get("mode", "permissive")
		noauth = config.get("noauth", mode == "permissive")
		accounts = config.get("accounts", [])


		blacklist = []
		for lr in config.get("blacklist", []):
			rule = ListingRule.make_from_dict(lr)
			blacklist.append(rule)

		whitelist = []
		for lr in config.get("whitelist", []):
			rule = ListingRule.make_from_dict(lr)
			whitelist.append(rule)

		overrides = config.get("overrides", [])
		overrides = list(map(lambda o: OverrideRule.make_from_dict(o), overrides))

		router = cls(
			mode=mode,
			accounts=accounts,
			blacklist=blacklist,
			whitelist=whitelist,
			overrides=overrides
		)

		return router

	def get_blacklisting(self, match:str) -> ListingRule:

		"""
		Find and return a ListingRule from the blacklist matching 'match'

		@param match: what to match i.e. host://google.com
		@raises IndexError: if no matching ListingRule is found.
		"""

		try:
			return list(filter(lambda lr: lr.match == match, self.blacklist))[0]
		except IndexError as error:
			raise error

	def get_whitelisting(self, match:str) -> ListingRule:

		"""
		Find and return a ListingRule from the whitelist matching 'match'

		@param match: what to match i.e. addr://192.168.1.0/24
		@raises IndexError: if no matching ListingRule is found.
		"""

		try:
			return list(filter(lambda lr: lr.match == match, self.whitelist))[0]
		except IndexError as error:
			raise error

	def add_host_override(self, host:str, override:str, users:list=[], roles:list=[]) -> None:

		"""
		Make a OverrideRule by 'host', 'override', 'users', 'rules' and add to the overrides list

		@param host: the host that the rule should match to be overridden i.e 192.168.1.1
		@param override: the host to that should be routed to instead of the host i.e. 192.168.1.120
		@param users: a list of account usernames that the rule should apply to
		@param roles: a list of account role names that the rule should apply to
		"""

		override = {"host": host, "override": override, "users": users, "roles": roles}
		override = OverrideRule.make_from_dict(override)
		self.overrides.append(override)

	def rem_host_override(self, host:str) -> None:

		"""
		Find an override rule by 'host' and remove from the overrides list

		@param host: the host that the rule overrides i.e. 192.168.1.1
		@raises IndexError: if no rule for that host was found
		"""

		try:
			override = list(filter(lambda o: o.host == host, self.overrides))[0]
		except IndexError as e:
			return

		self.overrides.remove(override)


	def add_host_blacklisting(self, match:str, roles:list[str]=[], users:list[str]=[]):

		"""
		Make a ListingRule by 'match', 'roles', 'users' and add to the blacklist

		@param match: what to match i.e. host://example.com
		@param users: a list of user names of accounts the rule should apply to
		@param roles: a list of role names of accounts the rule should apply to
		"""

		blacklisting = ListingRule.make_from_dict({"match": match, "roles": roles, "users": users})
		self.router_state.blacklist.append(blacklisting)

	def rem_host_blacklisting(self, match:str):

		"""
		Find the rule with the corresponding 'match' and remove from the blacklist

		@param match: the 'match' of the rule i.e. range://192.168.1.0/24
		"""

		blacklisting = self.router_state.get_blacklisting(match)
		self.router_state.blacklist.remove(blacklisting)

	def add_host_whitelisting(self, match:str, roles:list=[], users:list=[]):

		"""
		Make a ListingRule by 'match', 'roles', 'users' and add to the whitelist

		@param match: what to match i.e. host://example.com
		@param users: a list of user names of accounts the rule should apply to
		@param roles: a list of role names of accounts the rule should apply to
		"""

		whitelisting = ListingRule.make_from_dict({"match": match, "roles": roles, "users": users})
		self.router_state.whitelist.append(whitelisting)

	def rem_host_whitelisting(self, match:str):

		"""
		Find a whitelisting in the router state by 'match' and remove it

		@param match: the 'match' of the rule i.e. addr://192.168.1.1
		"""

		whitelisting = self.router_state.get_whitelisting(match)
		self.router_state.whitelist.remove(whitelisting)



@dataclass
class Router:

	state:RouterState
	accounts:list[Account]

	@property
	def blacklist(self):

		return self.state.blacklist

	@property
	def whitelist(self):

		return self.state.whitelist

	@property
	def overrides(self):

		return self.state.overrides

	def override_route(self, route:Route, account:Account) -> Route:

		try:
			override = list(filter(lambda o: o.matches(route, account), self.overrides))[0]
		except IndexError as e:
			raise OverrideError(f"no override set for {route.dst_host or route.dst_port}") from e

		users = override.users
		roles = override.roles

		if (not users and not roles) or (account.username in users or account.role in roles):
			port = override.ports.get(route.dst_port, route.dst_port)

			if re.match("^[0-9]{1,3}\.+[0-9]{1,3}\.+[0-9]{1,3}\.+[0-9]{1,3}$", override.override):
				addr = override.override
				return Route(addr, port, None)
			else:
				try:
					host = override.override
					addr = socket.gethostbyname(override.override)
					return Route(addr, port, host)
				except socket.gaierror:
					logger.info(f"failed to resolve address for override {override.host} -> {override.override}")
					return route
		else:
			raise OverrideError(f"rule doesn't match override criteria")

	def route(self, route:Route, account:Account) -> Route:

		mode = self.state.mode

		permitted = False
		if mode == "permissive":
			# check if there's a rule in the blacklist that matches this route
			# and if there isn't then routing to it is permitted.
			permitted = not bool(list(filter(lambda lr: lr.matches(route, account), self.state.blacklist)))
		elif mode == "restrictive":
			# check if there's a rule in the whitelist that matches this route
			# and if there is then routing to it is not permitted.
			permitted = bool(list(filter(lambda lr: lr.matches(route, account), self.state.whitelist)))

		if not permitted: raise BlacklistingError(f"{account.username} not permitted to access {route.dst_host or route.dst_addr}")

		try:
			route = self.override_route(route, account)
		except OverrideError as e:
			logger.info(e)

		return route

@dataclass
class Multiplexed:

	addr:str
	port:int
	sock:socket.socket

	@property
	def fileno(self):

		return self.sock.fileno

	def pack_establish(self) -> bytes:

		# 1 for establish
		return pack("!BB4sH", 5, 1, inet_aton(self.addr), self.port)

	def pack_data(self, data:bytes) -> bytes:

		# 2 for transfer
		dlen = len(data)
		packed = pack("!BB4sH", 5, 2, inet_aton(self.addr), self.port)
		packed += pack("!H", dlen)
		packed += data

		return packed

	def pack_close(self) -> bytes:

		# 3 for close
		return pack("!BB4sH", 5, 3, inet_aton(self.addr), self.port)

class SocksSession5(Thread):

	version:int = 5

	def __init__(self, client_sock:socket.socket, client_addr:tuple[str, int], router:Router, state:"SocksState"):

		"""
		@param client_sock: the client socket
		@param client_addr: a tuple of IP and source port of client
		@param router: the instance of the servers 'Router'
		@param state: the instance of the servers 'State'

		@ivar server_sock: the socket of what's being connected upstream
		@ivar server_addr: the IP and destination port of what is connected upstream
		@ivar active: weather or not the session is active and handling
		@ivar stop: the condition that the session should end on
		"""

		super().__init__()

		self.account = Account("anonymous_default", "anonymous_default", "anonymous_default")
		self.client_sock = client_sock
		self.client_addr = client_addr
		self.server_sock = None
		self.server_addr = None
		self.router = router
		self.state = state
		self.active = False
		self.stop = False

	def handle_connect(self, daddr:str, dport:int):

		"""
		Handle connecting to the requested destination,
		sets the server_sock

		@daddr: destination address (or hostname) of the server
		@dport: destination port of the server
		"""

		logging.info(f"daddr is {daddr} and dport is {dport}")
		self.server_sock = socket.socket()
		self.server_sock.connect(self.server_addr)
		response = pack("!BBBB4sH", 5, 0, 0, 1, inet_aton(daddr), dport)
		self.client_sock.sendall(response)

	def handle_authentication(self) -> None:


		""" handle the authentication sub negotiation """

		# maximum data scenario
		# version (1) + ulen (1) + uname (1-255) + pname (1) + passwd (1-255)
		buffer = io.BytesIO(self.client_sock.recv(515))
		version, ulength = unpack("BB", buffer.read(2))

		username = buffer.read(ulength).decode("latin-1")

		plength = unpack("B", buffer.read(1))[0]
		password = buffer.read(plength).decode("latin-1")

		for account in self.state.accounts:
			if account.username == username and account.password == password:
				logger.info(f"authentication with {username} successful!")
				break
		else:
			logger.info(f"authentication with {username} failed!")
			raise SocksAuthenticationError


		response = pack("BB", 5, 0)
		self.client_sock.sendall(response)

		self.account = account

	def handle_transfer(self):

		"""
		A function that polls both of the sockets
		with select and transfers data from one to the other.

		When neither are available to read/write there is
		a small sleep in order to avoid resource consumption.
		"""

		clist = [self.server_sock, self.client_sock]

		self.active = True
		while self.stop is False:
			rlist, wlist, elist = select(clist, clist, clist)
			if self.server_sock in wlist and self.client_sock in rlist:
				data = self.client_sock.recv(0xFFFF)
				if not data: break

				self.server_sock.sendall(data)
				logger.info("sent to client from server")
			elif self.client_sock in wlist and self.server_sock in rlist:
				data = self.server_sock.recv(0xFFFF)
				if not data: break

				self.client_sock.sendall(data)
				logger.info("sent to server from client")
			elif self.client_sock in elist or self.server_sock in elist:
				logger.info("an error happened with one of the sockets")
				break
			else:
				time.sleep(0.01)

			# check if the client is still connected by peeking the buffer (ughhh)
			# probably equivalent to MSG_DONTWAIT which isn't available on windows?

			# this may be inefficient and may or may not be wiser to put in the listener
			# to check the sessions and see this its self to terminate.

			# perhaps even we should just keep the socket in non-blocking mode
			# instead of technically switching it every single time?
			try:
				self.client_sock.settimeout(0)
				if not self.client_sock.recv(0xFFFF, MSG_PEEK): break
			except BlockingIOError as e:
				continue
			try:

				self.server_sock.settimeout(0)
				if not self.server_sock.recv(0xFFFF, MSG_PEEK): break
			except BlockingIOError as e:
				continue

		logger.info(f"terminating session {self.client_addr} -> {self.server_addr}")
		self.client_sock.close()
		self.server_sock.close()
		self.active = False

	def handle_multiplexing(self, baddr:str, bport:int) -> None:

		"""

		Binds to a port and handles multiplexing through
		addition to the protocol. Multiplexing is handled
		over subsequent frames and corresponding connections
		are distinguished by the source address and source port
		on the server which the client is notified of upon acceptance.

		+----+-------+-------+-------+----------------------+
		|VER |  CODE | SADDR | SPORT |   DLEN    |   DATA   |
		+----+-------+-------+-------+----------------------+
		| 1  |   1   |   4   |   2   |     2     | 1-65527  |
		+----+-------+-------+-------+----------------------+

		When a connection is accepted on the server a frame with
		an establish code will be sent to the multiplexing client
		allowing it to connect to an endpoint for forwarding.

		+----+-------+-------+-------+
		|VER |  CODE | SADDR | SPORT |
		+----+-------+-------+-------+
		| 1  | X'01' |   4   |   2   |
		+----+-------+-------+-------+

		When the multiplexing client recieves data from it's endpoint
		it will send back the source address and source port that it has
		on record as well as the length of the data followed by the data
		with the code set for "transfer". The server will then read the data
		from that frame and send it to the client it has on record with the
		provided source address and source port.

		+----+-------+-------+-------+----------------------+
		|VER |  CODE | SADDR | SPORT |   DLEN    |   DATA   |
		+----+-------+-------+-------+----------------------+
		| 1  | X'02' |   4   |   2   |     2     | 1-65527  |
		+----+-------+-------+-------+----------------------+

		The same will happen in reverse when the server recieves data from
		it's connected endpoint. It will package that data into a frame and
		send it to the multiplexing client.

		When the server or client lose connection to their endpoints they'll
		notify the other one to close the connection with a "close" code.


		+----+-------+-------+-------+
		|VER |  CODE | SADDR | SPORT |
		+----+-------+-------+-------+
		| 1  | X'03' |   4   |   2   |
		+----+-------+-------+-------+


		@param baddr: the IPv4 address of the interface to bind to
		@param bport: the port to bind to
		"""

		self.active = True

		class SessionError(Exception):

			pass

		class MultiplexerError(Exception):

			pass

		listen_sock = socket.socket()
		listen_sock.bind((baddr, bport))
		listen_sock.listen(100)

		sessions = []

		def handle_accept():

			sock, addr = listen_sock.accept()

			logger.info(f"{baddr}:{bport} accepted {addr[0]}:{addr[1]}")
			session = Multiplexed(addr[0], addr[1], sock)
			sessions.append(session)

			self.client_sock.sendall(session.pack_establish())

		def handle_request_multiplexer():

			""" recieve and handle the request of the client """

			data = self.client_sock.recv(0xFFFF)
			if not data: raise MultiplexerError

			buffer = io.BytesIO(data)

			version, code, saddr, sport = unpack("!BB4sH", buffer.read(8))
			saddr = inet_ntoa(saddr)

			try:
				session = list(filter(lambda m: m.addr == saddr and m.port == sport, sessions))[0]
			except IndexError:
				session = None

			if code == 2 and session:
				dlen = unpack("!H", buffer.read(2))[0]
				data = buffer.read(dlen)
				session.sock.sendall(data)
			elif code == 3 and session:
				self.client_sock.sock.sendall(session.pack_close())
				session.sock.close()
				sessions.remove(session)

		def handle_request_client(session):

			""" handle the request from the socket connected to the listening port """

			data = session.sock.recv(0xFFFF - 8)

			if data:
				packed = session.pack_data(data)
			else:
				logger.info(f"empty response recieved from session {session.addr} {session.port}")
				logger.info("sending close command for session to the multiplexing client")
				sessions.remove(session)
				packed = session.pack_close()

			try:
				self.client_sock.sendall(packed)
			except socket.error as e:
				raise MultiplexerError("failed to send data to multiplexing client") from e

		while self.stop is False:

			accept_ready, _, _ = select([listen_sock], [], [], 0.1)
			if accept_ready:
				handle_accept()

			clist = sessions + [self.client_sock]
			rlist, wlist, xlist = select(clist, clist, clist)

			if self.client_sock in rlist:

				try:
					handle_request_multiplexer()
				except MultiplexerError as e:
					logger.info(str(e))
					break

			for session in rlist:
				if session is self.client_sock: continue

				try:
					handle_request_client(session)
				except MultiplexerError as e:
					logger.info(str(e)); break

		self.client_sock.close()
		listen_sock.close()
		for session in sessions:
			session.sock.close()

		self.active = False

	def handle_session(self) -> None:

		"""
		Complete the negotations and handle the
		session in the relevent way to the command used.

		This method raises various SocksError exceptions
		under the circumstance of errors. The corresponding
		error can be excepted and an appropriate response can
		be sent from an except of a try block handling this method.
		"""

		logger.info("handling negotation")
		# handle the method selection

		buffer = io.BytesIO(self.client_sock.recv(258))
		version, nmethods = unpack("BB", buffer.read(2))
		# read and methods and choose what we're going to use.
		methods = buffer.read(nmethods)
		# bytes can be searched through using an int up to 255, duh.

		# 0 for no authentication
		# 2 for username and password
		# 255 for no supported methods


		# It has become evident that some clients will
		# send other methods for selection even when the user
		# specifies to use username/password authentication

		# Thus fourth the authentication method must be checked for first
		if 2 in methods:
			response = pack("BB", 5, 2)
			self.client_sock.sendall(response)
			self.handle_authentication()
		elif 1 in methods and self.state.noauth:
			response = pack("BB", 5, 0)
			self.client_sock.sendall(response)
		else:
			raise SocksMethodError

		# handle the request

		# the maximum length requirement scenario:
		#
		# version (1) + command (1) + reserved(1) +
		# address type (1) + fqdn length (1) + fqdn (1-255) +
		# destination port (2) : 261 bytes maximum

		buffer = io.BytesIO(self.client_sock.recv(261))
		version, cmd, rsv, atype = unpack("BBBB", buffer.read(4))

		# 1 for connect
		# 2 for bind
		# 3 for udp associate

		if cmd == 1:
			# 1 for IPv4
			# 2 for IPv6
			# 3 for FQDN

			host = None
			if atype == 1:
				addr = inet_ntoa(buffer.read(4))
				port = unpack("!H", buffer.read(2))[0]
			elif atype == 3:
				length, = unpack("B", buffer.read(1))
				host = buffer.read(length).decode()
				addr = socket.gethostbyname(host)
				port = unpack("!H", buffer.read(2))[0]
			else:
				raise SocksAddressError

			route = Route(addr, port, host)
			try:
				# ask the router for where to actually go with this
				route = self.router.route(route, self.account)
				print("setting the server addr")
				self.server_addr = (route.dst_addr, route.dst_port)
				print("server addr is", self.server_addr)
			except (RoutingError, BlacklistingError) as error:
				raise error

			self.handle_connect(self.server_addr[0], self.server_addr[1])
			self.handle_transfer()
		elif cmd == 4:
			if atype == 1:
				addr = inet_ntoa(buffer.read(4))
				port = unpack("!H", buffer.read(2))[0]
				if port in self.state.bound_ports:
					raise SocksBindError(f"{port} already taken")
			else:
				raise SocksRoutingError
			try:

				self.handle_multiplexing(addr, port)
			except Exception as e:
				logging.info(f"something went wrong with multiplexing for {addr}:{port} {e}")
		else:
			raise SocksCommandError(f"command {cmd} not supported")

	def run(self):

		""" Start and handle the socks session """

		error = None
		etype = None
		response = None
		try:
			self.handle_session()
		except (SocksError, RoutingError) as e:
			# send a reply based on the error
			error = e
			etype = type(e)
			if etype is SocksMethodError:
				# 255 for no supported methods
				response = pack("BB", 5, 255)
			elif etype is SocksCommandError:
				# 7 for command not supported
				response = pack("BB", 5, 7)
			elif etype is SocksAddressError:
				# 8 for address type not supported
				response = pack("BB", 5, 8)
			elif etype is SocksBindError:
				# 1 for general server error
				resposne = pack("BB", 1)
			elif etype is RoutingError:
				# 4 for host unreachable
				response = pack("BB", 5, 4)
			if response: self.client_sock.sendall(response); return
		finally:
			self.client_sock.close()
			if self.server_sock:
				self.server_sock.close()

@dataclass
class SocksState:

	addr:str
	port:int
	noauth:bool
	accounts:list[Account] = field(default_factory=list)
	sessions:list[SocksSession5] = field(default_factory=list)
	bound_ports:list[int] = field(default_factory=list)

	@classmethod
	def make_from_dict(cls, config:dict) -> "SocksState":

		addr = config.get("addr", "0.0.0.0")
		port = config.get("port", 1080)
		noauth = config.get("noauth", False)

		return cls(addr, port, noauth)

class SocksServer5(Thread):

	def __init__(self, state:SocksState, router:Router):

		super().__init__()

		self.addr = (state.addr, state.port)
		self.sock = socket.socket(AF_INET, SOCK_STREAM)
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.stop = False
		self.state = state
		self.router = router
		self.sessions = []

	def run(self):

		self.state.sessions = self.sessions
		self.sock.bind(self.addr)
		self.sock.listen(100)
		logger.info(f"socks server bound and listening on {self.addr}")

		while self.stop is False:
			client_sock, client_addr = self.sock.accept()
			session = SocksSession5(client_sock, client_addr, self.router, self.state)
			logger.info(f"accepted connection and starting session with {client_addr[0]}:{client_addr[1]}")
			session.start()

			self.sessions.append(session)

@dataclass
class ApplicationState:

	accounts:list[Account]
	socks_state:SocksState
	router_state:RouterState
	conf_path = None # only used if made using make_from_config method

	@classmethod
	def make_from_dict(cls, config:dict):

		accounts = [Account(a["username"], a["password"], a.get("role", "default")) for a in config.get("accounts", [])]

		socks_state = SocksState.make_from_dict(config.get("server", {}))
		socks_state.accounts = accounts
		router_state = RouterState.make_from_dict(config.get("router", {}))

		return cls(accounts, socks_state, router_state)

	@classmethod
	def make_from_config(cls, path:str) -> "ApplicationState":


		with open(path, "r") as f:
			config = json.load(f)

		instance = cls.make_from_dict(config)
		instance.conf_path = path

		return instance

	def save_to_config(self, path:str=None):

		self.conf_path = path if path else self.config_path
		with open(path, "w") as f:
			json.dump(asdict(self), f, dent="\t")

	@property
	def add_host_override(self):

		return self.router_state.add_host_override

	@property
	def rem_host_override(self):

		return self.router_state.rem_host_override

	@property
	def add_host_blacklisting(self):

		return self.router_state.add_host_blacklisting

	@property
	def rem_host_blacklisting(self):

		return self.router_state.rem_host_blacklisting

	@property
	def add_host_whitelisting(self, match:str, roles:list=[], users:list=[]):

		return self.router_state.add_host_whitelisting

	@property
	def rem_host_whitelisting(self, match:str):

		return self.router_state.rem_host_whitelisting

def main():
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--config-file", help="path to config file")
	arguments = parser.parse_args()

	if arguments.config_file:
		appstate = ApplicationState.make_from_config("default/config/restrictive.json")
	else:
		logger.info("no configuration file was specified. server will start with default settings.")
		appstate = ApplicationState.make_from_dict({})


	logger.info(f"router mode is mode {appstate.router_state.mode}")
	logger.info(f"socks server will bind to {appstate.socks_state.addr}:{appstate.socks_state.port}")

	router = Router(appstate.router_state, appstate.accounts)
	server = SocksServer5(appstate.socks_state, router)
	logger.info(f"attempting to start the socks server")
	server.start()
	server.join()

if __name__ == "__main__":
	main()
