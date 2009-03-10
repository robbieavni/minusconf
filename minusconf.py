#!/usr/bin/env python
"""
minusconf is a service location protocol.
Unlike SSDP/UPnP/ZeroConf/SLP and friends, it works without any configuration anywhere, is lightweight (this file is the whole implementation), allows multiple hosts per service without any configuration between the services and survives turning off arbitrary hosts as well as subnets.
However, it lacks device descriptions, abonnements and unsolicited advertisements.


minusconf advertisers listen on UDP port 6376 on the multicast groups 239.45.99.98 and/or ff08::6d69:6e75:7363:6f6e:6600.

Every minusconf packet starts with 0xadc3e6e7.
The next byte is the opcode, between 0 and 99 for seekers and 100 and 199 for advertisers.
The format of the rest of the message depends on the opcode. Any data after the here defined must be ignored.
For the rest of this text, let a string(S) consist of any number of Unicode characters encoded in UTF-8 ending with '\0'.

1 Query(S advertisername, S servicetype, S servicename)

Asks for service locations. An empty string matches any value.
servicetype can be any name in http://www.iana.org/assignments/port-numbers or another name server and client agree to use.

101 Advertisement (S advertisername, S servicetype, S servicename, S location, S port)

A response to a query. advertisername, servicetype and servicename are usually copied from the query. If the client asked for ""(any value), advertisers should fill in a preferred value. (Because an empty servicetype makes no sense, advertisers must fill in a value in this case). If location is not empty, it is a string representation of an address that must be used to initiate a connection. The port argument is inteded for a UDP or TCP port, but can also be used to transfer any other application-specific data. Servers may send multiple advertisement packages, hence clients must ignore repeated identical advertisements.

111 Error (S message)

(Optional) reply to an invalid or unanswerable query. Must not be sent in response to a message with opcode != 1 and should not be sent if magic is not present.


This implementation is licensensed under the Apache License 2.0.
"""

import struct
import socket
import threading
import time

_PORT = 6376
_ADDRESS_4 = '239.45.99.98'
_ADDRESS_6 = 'ff08:0:0:6d69:6e75:7363:6f6e:6600'
_ADDRESSES = [_ADDRESS_4]
if socket.has_ipv6:
	_ADDRESSES.append(_ADDRESS_6)
_CHARSET = 'UTF-8'

_MAGIC = struct.pack('!I', 0xadc3e6e7) # b'\xad\xc3\xe6\xe7' , but works in python<2.6 *and* >=3
_OPCODE_QUERY = struct.pack('!B', 0x01) # b'\x01'
_OPCODE_ADVERTISEMENT = struct.pack('!B', 0x65) # b'\x65'
_OPCODE_ERROR = struct.pack('!B', 0x6f) # b'\x6f'
_STRING_TERMINATOR = struct.pack('!B', 0x00) # b'\0'

# Biggest packet size this implementation will accept"""
_MAX_PACKET_SIZE = 2048
_SEEKER_TIMEOUT = 2.0 # Timeout for seeks in s

class MinusconfError(Exception):
	def __init__(self, msg=''):
		super(MinusconfError, self).__init__()
		self.msg = msg
	
	def send(self, sock, to):
		_send_packet(sock, to, _OPCODE_ERROR, _encode_string(self.msg))

class _ImmutableStruct(object):
	""" Helper structure for immutable objects """
	
	def __setattr__(self, *args):
		raise TypeError("This structure is immutable")
	__delattr__ = __setattr__
	
	def __init__(self, values):
		for (k,v) in values.items():
			super(_ImmutableStruct, self).__setattr__(k, v)
	
	def __cmp__(self, other):
		return cmp(self.__dict__, other.__dict__)
	
	def __hash__(self):
		return hash(sum((hash(i) for i in self.__dict__.items())))

class Service(_ImmutableStruct):
	""" Helper structure for a service."""
	
	def __init__(self, stype, port, name="", location="", addAttrs={}):
		addAttrs.update({"stype": stype, "port":port, "name": name, "location":location})
		super(Service, self).__init__(addAttrs)
	
	def matches_query(self, stype, name):
		return _string_match(stype, self.stype) and _string_match(name, self.name)
	
	def __repr__(self):
		res = self.stype + " service at "
		if self.name != "": res += self.name + " "
		res += self.location + ":" + self.port
		
		return res

class ServiceAt(Service):
	def __init__(self, aname, stype, sname, location, port, addr, addAttrs={}):
		addAttrs.update({"aname": aname, "addr":addr})
		super(ServiceAt, self).__init__(stype, port, sname, location, addAttrs)
	
	def matches_query_at(self, aname, stype, sname):
		return self.matches_query(stype, sname) and _string_match(aname, self.aname)
	
	@property
	def effective_location(self):
		return self.location if self.location != "" else self.addr
	
	def __repr__(self):
		return super(ServiceAt, self).__repr__() + " (advertiser \"" + self.aname + "\" at " + self.addr + ")"

class Advertiser(object):
	""" Implementation of a -conf advertiser."""
	
	def __init__(self, services=[], aname=None, port=_PORT, addresses=_ADDRESSES):
		self.__services = services
		self.__slock = threading.RLock()
		self.aname = aname if aname != "" else socket.gethostname()
		self.port = port
		self.addresses = addresses
	
	def add_service(self, svc):
		self.__slock.acquire()
		self.__services.append(svc)
		self.__slock.release()
	
	def remove_service(self, svc):
		self.__slock.acquire()
		try:
			self.__services.remove(svc)
		except ValueError:
			pass
		finally:
			self.__slock.release()
	
	def run_forever(self):
		""" Runs the advertiser until error """
		threads = self.run_background()
		
		for t in threads:
			t.join()
	
	def run_background(self, daemonized=True):
		""" Runs the advertiser in a number of spawned threads which are returned. """
		aiss = _getaddrinfos(self.addresses)
		
		res = []
		for ais in aiss:
			if len(ais) == 0:
				continue
			
			t = threading.Thread(target=self.__run_on_addressinfos, args=(ais,))
			t.setDaemon(daemonized)
			
			res.append(t)
			t.start()
		
		return res
	
	def __run_on_addressinfos(self, ais):
		""" Runs the advertiser and listens to all addressinfos in ais """
		sock = _multicast_mult_receiver(ais[0][0], ais, self.port, True)
		
		self.__run_on_sock(sock)
	
	def __run_on_sock(self, sock):
		""" Listens to queries on a fully configured socket. """
		while True:
			opcode, data, sender = _parse_packet(sock)
			
			if opcode == _OPCODE_QUERY:
				try:
					self.__handle_query(sock, sender, data)
				except MinusconfError, mce:
					mce.send(sock, sender)
				# To be really verbose, uncomment the following two lines
				#except BaseException, be:
				#	MinusconfError(str(be)).send(sock, sender)
	
	def services_matching(self, stype, sname):
		self.__slock.acquire()
		res = filter(lambda svc: svc.matches_query(stype, sname), self.__services)
		self.__slock.release()
		
		return res
	
	def __handle_query(self, sock, sender, qrydata):
		qaname,p = _decode_string(qrydata, 0)
		qstype,p = _decode_string(qrydata, p)
		qsname,p = _decode_string(qrydata, p)
		
		if _string_match(qaname, self.aname):
			for svc in self.services_matching(qstype, qsname):
				rply = _encode_string(self.aname) + _encode_string(svc.stype) + _encode_string(svc.name) + _encode_string(svc.location) + _encode_string(svc.port)
				
				_send_packet(sock, sender, _OPCODE_ADVERTISEMENT, rply)

class Seeker(object):
	""" find_callback is called with (this_seeker,found_service_at) """
	def __init__(self, servicetype="", advertisername="", servicename="", timeout=_SEEKER_TIMEOUT, port=_PORT, addresses=_ADDRESSES, find_callback=None):
		self.timeout = timeout
		self.port = port
		self.addresses = addresses
		self.find_callback = find_callback
		self.__flock = threading.RLock()
		self.reset(servicetype, advertisername, servicename)
	
	def reset(self, servicetype="", advertisername="", servicename=""):
		self.servicetype = servicetype
		self.advertisername = advertisername
		self.servicename = servicename
		
		self.results = set()
	
	def seek_blocking(self):
		threads = self.seek_background()
		
		for t in threads:
			t.join()
	
	""" Returns the spawned threads."""
	def seek_background(self, daemonized=True):
		self.__starttime = time.time()
		
		aiss = _getaddrinfos(self.addresses)
		
		res = []
		for ais in aiss:
			if len(ais) == 0:
				continue
			
			t = threading.Thread(target=self.__seek_on_addressinfos, args=(ais,))
			t.setDaemon(daemonized)
			
			res.append(t)
			t.start()
		
		return res
	
	def __seek_on_addressinfos(self, ais):
		sock = _multicast_sender(ais[0][0])
		for ai in ais:
			self.__send_query(sock, (ai[4][0], self.port))
		
		while True:
			timeout = self.timeout - (time.time() - self.__starttime)
			if timeout < 0:
				break
			
			sock.settimeout(timeout)
			try:
				opcode,data,sender = _parse_packet(sock)
				
				if opcode == _OPCODE_ADVERTISEMENT:
					self.__handle_advertisement(data, sender)
			except socket.timeout:
				break
	
	def __send_query(self, sock, to):
		binqry = _encode_string(self.advertisername)
		binqry += _encode_string(self.servicetype)
		binqry += _encode_string(self.servicename)
		
		_send_packet(sock, to, _OPCODE_QUERY, binqry)
	
	def __handle_advertisement(self, bindata, sender):
		aname,p = _decode_string(bindata, 0)
		stype,p = _decode_string(bindata, p)
		sname,p = _decode_string(bindata, p)
		location,p = _decode_string(bindata, p)
		port,p = _decode_string(bindata, p)
		
		svca = ServiceAt(aname, stype, sname, location, port, sender[0])
		if svca.matches_query_at(self.advertisername, self.servicetype, self.servicename):
			self.__found_result(svca)
	
	def __found_result(self, result):
		self.__flock.acquire()
		try:
			if not (result in self.results):
				self.results.add(result)
				if self.find_callback != None:
					self.find_callback(self, result)
		finally:
			self.__flock.release()

def _send_packet(sock, to, opcode, data):
	sock.sendto(_MAGIC + opcode + data, 0, to)

def _parse_packet(sock):
	""" Returns a tupel (opcode, data, sender). opcode is None if this isn't a -conf packet."""
	
	data, sender = sock.recvfrom(_MAX_PACKET_SIZE)
	
	if (len(data) < len(_MAGIC) + 1) or (_MAGIC != data[:len(_MAGIC)]):
		# Wrong protocol
		return (None, None, None)
	
	opcode = data[len(_MAGIC)]
	payload = data[len(_MAGIC)+1:]
	
	return (opcode, payload, sender)

def _encode_string(val):
	return val.encode(_CHARSET) + _STRING_TERMINATOR

def _decode_string(buf, pos):
	""" Decodes a string in the buffer buf, starting at position pos.
	Returns a tupel of the read string and the next byte to read.
	"""
	for i in range(pos, len(buf)):
		if buf[i] == '\0':
			break
	else:
		raise MinusconfError("Premature end of string (Forgot trailing \\0?)")
	
	return (buf[pos:i].decode(_CHARSET), i+1)

def _string_match(query, value):
	return query == "" or query == value

def _multicast_sender(family, ttl=None):
	s = socket.socket(family, socket.SOCK_DGRAM)
	
	if ttl != None:
		ttl_bin = struct.pack('@i', ttl)
		if family == socket.AF_INET:
			s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
		else:
			s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl_bin)
	
	return s

def _multicast_receiver(addr, port, reuse=True):
	addrinfo = socket.getaddrinfo(addr, None)[0]
	multicast_mult_receiver(addrinfo[0], [addrinfo], port, reuse)

def _multicast_mult_receiver(family, addrinfos, port, reuse=True):
	s = socket.socket(family, socket.SOCK_DGRAM)
	
	if reuse:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	
	s.bind(('', port))
	
	for ai in addrinfos:
		_multicast_join_group(s, ai)
	
	return s

def _multicast_join_group(sock, addrinfo):
	group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
	if sock.family == socket.AF_INET: # IPv4
		mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
	else: # IPv6
		mreq = group_bin + struct.pack('@I', 0)
		sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

""" Returns a tupel of IPv4 and IPv6 getaddrinfo results """
def _getaddrinfos(addrstrs, silentIgnore=True):
	v4s = []
	v6s = []
	
	for addrstr in addrstrs:
		try:
			ai = socket.getaddrinfo(addrstr, None)[0]
			
			if ai[0] == socket.AF_INET:
				v4s.append(ai)
			else:
				v6s.append(ai)
		except:
			if not silentIgnore:
				raise
	
	return (v4s, v6s)

def _main():
	""" CLI interface """
	import sys
	
	if len(sys.argv) < 2:
		_usage('Expected at least two arguments!')
	
	sc = sys.argv[1]
	options = sys.argv[2:]
	if sc == 'a' or sc == 'advertise':
		if len(options) > 5 or len(options) < 2:
			_usage()
		
		stype,port = options[:2]
		advertisername = options[2] if len(options) > 2 else ''
		sname = options[3] if len(options) > 3 else ''
		slocation = options[4] if len(options) > 4 else ''
		
		service = Service(stype, port, sname, slocation)
		advertiser = Advertiser([service], advertisername)
		advertiser.run_forever()
	elif sc == 's' or sc == 'seek':
		if len(options) > 4:
			_usage()
		
		aname = options[0] if len(options) > 0 else ''
		stype = options[1] if len(options) > 1 else ''
		sname = options[2] if len(options) > 2 else ''
		
		se = Seeker(aname, stype, sname, find_callback=_print_result)
		se.seek_blocking()
	else:
		_usage('Unknown subcommand "' + sys.argv[0] + '"')

def _print_result(seeker, svca):
	print ("Found " + str(svca))

def _usage(note=None, and_exit=True):
	import sys
	
	if note != None:
		print("Error: " + note + "\n")
	
	print("Usage: " + sys.argv[0] + " subcommand options...")
	print("\ta[dvertise] servicetype port [advertisername [servicename [location]]]")
	print("\ts[eek]      [servicetype [advertisername [servicename]]]")
	print('Use "" for default/any value.')
	print("Examples:")
	print("\t" + sys.argv[0] + " advertise http 80 fastmachine Apache")
	print("\t" + sys.argv[0] + ' seek http "" Apache')
	
	if and_exit:
		sys.exit(0)

if __name__ == "__main__":
	_main()
