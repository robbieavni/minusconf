#!/usr/bin/env python
"""
Implementation of the minusconf protocol. See http://code.google.com/p/minusconf/ for details.
Apache License 2.0, see the LICENSE file for details.
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

try:
	if bytes != str: # Python 3+
		_compat_bytes = lambda bytestr: bytes(bytestr, 'charmap')
	else: # 2.6+
		_compat_bytes = str
except: # <2.6
	_compat_bytes = str

_MAGIC = _compat_bytes('\xad\xc3\xe6\xe7')
_OPCODE_QUERY = _compat_bytes('\x01')
_OPCODE_ADVERTISEMENT = _compat_bytes('\x65')
_OPCODE_ERROR = _compat_bytes('\x6f')
_STRING_TERMINATOR = _compat_bytes('\x00')

_TTL = None
_MAX_PACKET_SIZE = 2048 # Biggest packet size this implementation will accept"""
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
	
	def __eq__(self, other):
		return self.__dict__ == other.__dict__
	
	def __ne__(self, other):
		return self.__dict__ != other.__dict__
	
	def __lt__(self, other):
		return self.__dict__ < other.__dict__
	
	def __le__(self, other):
		return self.__dict__ <= other.__dict__
	
	def __gt__(self, other):
		return self.__dict__ > other.__dict__
	
	def __ge__(self, other):
		return self.__dict__ >= other.__dict__
	
	def __hash__(self):
		return hash(sum((hash(i) for i in self.__dict__.items())))

class Service(_ImmutableStruct):
	""" Helper structure for a service."""
	
	def __init__(self, stype, port, sname='', location=''):
		super(Service, self).__init__({'stype': stype, 'port':port, 'sname': sname, 'location':location})
	
	def matches_query(self, stype, sname):
		return _string_match(stype, self.stype) and _string_match(sname, self.sname)
	
	def __str__(self):
		res = self.stype + ' service at '
		if self.sname != '': res += self.sname + ' '
		res += self.location + ':' + self.port
		
		return res
	
	def __repr__(self):
		return ('Service(' +
			repr(self.stype) + ', ' +
			repr(self.port) + ', ' +
			repr(self.sname) + ', ' +
			repr(self.location) + ')')

class ServiceAt(_ImmutableStruct):
	""" A service returned by an advertiser"""
	
	def __init__(self, aname, stype, sname, location, port, addr):
		super(ServiceAt, self).__init__(
			{'aname': aname, 'stype': stype, 'sname': sname, 'location': location, 'port': port, 'addr':addr}
		)
	
	def matches_query_at(self, aname, stype, sname):
		return _string_match(stype, self.stype) and _string_match(sname, self.sname) and _string_match(aname, self.aname)
	
	@property
	def effective_location(self):
		return self.location if self.location != "" else self.addr
	
	def __str__(self):
		return (
			self.stype + ' service at ' +
			((self.sname + ' ') if self.sname != '' else '') +
			self.location + ':' + self.port +
			' (advertiser "' + self.aname + '" at ' + self.addr + ')'
			)
	
	def __repr__(self):
		return ('ServiceAt(' +
			repr(self.aname) + ', ' +
			repr(self.stype) + ', ' +
			repr(self.sname) + ', ' +
			repr(self.location) + ', ' +
			repr(self.port) + ', ' +
			repr(self.addr) + ')')


class Advertiser(threading.Thread):
	""" Implementation of a -conf advertiser."""
	
	def __init__(self, services=[], aname=None, port=_PORT, addresses=_ADDRESSES, daemonized=True):
		super(Advertiser, self).__init__()
		
		self.services = services
		self.aname = aname if aname != None else socket.gethostname()
		self.port = port
		self.addresses = addresses
		self.setDaemon(daemonized)
		self.__ready = threading.Event()
	
	def start_blocking(self):
		""" Start the advertiser in a new thread, but wait until it is ready """
		
		self.__ready.clear()
		self.start()
		self.__ready.wait()
	
	def run(self):
		try:
			common_family,addrfams = _addressfamilies(self.addresses, None, auto_convert=False)
			
			sock = socket.socket(common_family, socket.SOCK_DGRAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind(('', self.port))
			for fam,addr,to in addrfams:
				_multicast_join_group(sock, fam, addr)
		finally:
			self.__ready.set()
		
		self.__run_on_sock(sock)
	
	def __run_on_sock(self, sock):
		""" Listens to queries on a fully configured socket. """
		while True:
			opcode, data, sender = _parse_packet(sock)
			
			if opcode == _OPCODE_QUERY:
				try:
					self.__handle_query(sock, sender, data)
				# Comment the following lines out for proper error handling (Python 2.6+)
				#except MinusconfError as mce:
				#	mce.send(sock, sender)
				#except BaseException as be:
				#	MinusconfError(str(be)).send(sock, sender)
				
				# Silent error handling
				except (MinusconfError, BaseException):
					pass
				
	
	def services_matching(self, stype, sname):
		return filter(lambda svc: svc.matches_query(stype, sname), self.services)
	
	def __handle_query(self, sock, sender, qrydata):
		qaname,p = _decode_string(qrydata, 0)
		qstype,p = _decode_string(qrydata, p)
		qsname,p = _decode_string(qrydata, p)
		
		if _string_match(qaname, self.aname):
			for svc in self.services_matching(qstype, qsname):
				rply = (
					_encode_string(self.aname) +
					_encode_string(svc.stype) +
					_encode_string(svc.sname) +
					_encode_string(svc.location) +
					_encode_string(svc.port)
					)
				
				_send_packet(sock, sender, _OPCODE_ADVERTISEMENT, rply)

class Seeker(threading.Thread):
	""" find_callback is called with (this_seeker,found_service_at)
	error_callback is called with (this seeker, sender, error message) """
	def __init__(self, servicetype="", advertisername="", servicename="", timeout=_SEEKER_TIMEOUT, port=_PORT, addresses=_ADDRESSES, find_callback=None, error_callback=None, daemonized=True):
		super(Seeker, self).__init__()
		
		self.timeout = timeout
		self.port = port
		self.addresses = addresses
		self.find_callback = find_callback
		self.error_callback = error_callback
		self.setDaemon(daemonized)
		self.reset(servicetype, advertisername, servicename)
	
	def reset(self, servicetype="", advertisername="", servicename=""):
		self.servicetype = servicetype
		self.advertisername = advertisername
		self.servicename = servicename
		
		self.results = set()
	
	def run(self):
		common_family,addrfams = _addressfamilies(self.addresses, self.port, auto_convert=True)
		
		sock = socket.socket(common_family, socket.SOCK_DGRAM)
		_multicast_configure_sender(sock, _TTL)
		
		for fam,addr,to in addrfams:
			self.__send_query(sock, to)
		
		self.__read_replies(sock)
	
	def __read_replies(self, sock):
		starttime = time.time()
		while True:
			timeout = self.timeout - (time.time() - starttime)
			if timeout < 0:
				break
			
			sock.settimeout(timeout)
			try:
				opcode,data,sender = _parse_packet(sock)
				
				if opcode == _OPCODE_ADVERTISEMENT:
					self.__handle_advertisement(data, sender)
				elif opcode == _OPCODE_ERROR:
					try:
						error_str = _decode_string(data, 0)[0]
					except:
						error_str = '[Error when trying to read error message ' + repr(data) + ']'
					
					if self.error_callback != None:
							self.error_callback(self, sender, error_str)
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
		if not (result in self.results):
			self.results.add(result)
			if self.find_callback != None:
				self.find_callback(self, result)

def _send_packet(sock, to, opcode, data):
	sock.sendto(_MAGIC + opcode + data, 0, to)

def _parse_packet(sock):
	""" Returns a tupel (opcode, data, sender). opcode is None if this isn't a -conf packet."""
	
	data, sender = sock.recvfrom(_MAX_PACKET_SIZE)
	
	if (len(data) < len(_MAGIC) + 1) or (_MAGIC != data[:len(_MAGIC)]):
		# Wrong protocol
		return (None, None, None)
	
	opcode = data[len(_MAGIC):len(_MAGIC)+1]
	payload = data[len(_MAGIC)+1:]
	
	return (opcode, payload, sender)

def _encode_string(val):
	return val.encode(_CHARSET) + _STRING_TERMINATOR

def _decode_string(buf, pos):
	""" Decodes a string in the buffer buf, starting at position pos.
	Returns a tupel of the read string and the next byte to read.
	"""
	for i in range(pos, len(buf)):
		if buf[i:i+1] == _compat_bytes('\x00'):
			return (buf[pos:i].decode(_CHARSET), i+1)
	
	raise MinusconfError("Premature end of string (Forgot trailing \\0?), buf=" + repr(buf))

def _string_match(query, value):
	return query == "" or query == value

def _multicast_configure_sender(sock, ttl=None):
	if ttl != None:
		ttl_bin = struct.pack('@i', ttl)
		
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
		if socket.has_ipv6:
			sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl_bin)

def _multicast_join_group(sock, family, addr):
	group_bin = _inet_pton(family, addr)
	if family == socket.AF_INET: # IPv4
		mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
	elif family == socket.AF_INET6: # IPv6
		mreq = group_bin + struct.pack('@I', 0)
		sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
	else:
		raise ValueError('Unsupported protocol family ' + family)

def _addressfamilies(straddrs, port, ignore_unavailable=False, auto_convert=True):
	""" Returns a tupel (common address family, ((family, addr, to), ...)).
	Common address family is IPv4 iff only IPv4 addresses have been supplied.
	Note that to may be of a different address family, but addr is guaranteed to be of the same family.
	If ignore_unavailable is set, addresses for unavailable protocols are ignored.
	If auto_convert is set, IPv6 is always used"""
	
	addrs = [] # Addresses
	common_family = socket.AF_INET
	for sa in straddrs:
		try:
			ai = socket.getaddrinfo(sa, port)[0]
			family = ai[0]
			to = ai[4]
			addr = ai[4][0]
			
			if auto_convert and socket.has_ipv6 and family == socket.AF_INET:
				to = socket.getaddrinfo('::ffff:' + addr, port)[0][4]
				common_family = socket.AF_INET6
			
			addrs.append((family, addr, to))
			
			if family == socket.AF_INET6:
				common_family = socket.AF_INET6
		except:
			if not ignoreUnavailable:
				raise
	
	return (common_family,addrs)

def _main():
	""" CLI interface """
	import sys
	
	if len(sys.argv) < 2:
		_usage('Expected at least one parameter!')
	
	sc = sys.argv[1]
	options = sys.argv[2:]
	if sc == 'a' or sc == 'advertise':
		if len(options) > 5 or len(options) < 2:
			_usage()
		
		stype,port = options[:2]
		advertisername = options[2] if len(options) > 2 else None
		sname = options[3] if len(options) > 3 else ''
		slocation = options[4] if len(options) > 4 else ''
		
		service = Service(stype, port, sname, slocation)
		advertiser = Advertiser([service], advertisername)
		advertiser.run()
	elif sc == 's' or sc == 'seek':
		if len(options) > 4:
			_usage()
		
		aname = options[0] if len(options) > 0 else ''
		stype = options[1] if len(options) > 1 else ''
		sname = options[2] if len(options) > 2 else ''
		
		se = Seeker(aname, stype, sname, find_callback=_print_result, error_callback=_print_error)
		se.run()
	else:
		_usage('Unknown subcommand "' + sys.argv[0] + '"')

def _print_result(seeker, svca):
	print ("Found " + str(svca))

def _print_error(seeker, opposite, error_str):
	import sys
	sys.stderr.write("Error from " + str(opposite) + ": " + error_str + "\n")

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

def _compat_inet_pton(family, addr):
	""" socket.inet_pton for platforms that don't have it """
	
	if family == socket.AF_INET:
		# inet_aton accepts some strange forms, so we use our own
		res = _compat_bytes('')
		parts = addr.split('.')
		if len(parts) != 4:
			raise ValueError('Expected 4 dot-separated numbers')
		
		for part in parts:
			intval = int(part, 10)
			if intval < 0 or intval > 0xff:
				raise ValueError("Invalid integer value in IPv4 address: " + str(intval))
			
			res = res + struct.pack('!B', intval)
		
		return res
	elif family == socket.AF_INET6:
		wordcount = 8
		res = _compat_bytes('')
		
		# IPv4 embedded?
		dotpos = addr.find('.')
		if dotpos >= 0:
			v4start = addr.rfind(':', 0, dotpos)
			if v4start == -1:
				raise ValueException("Missing colons in an IPv6 address")
			wordcount = 6
			res = socket.inet_aton(addr[v4start+1:])
			addr = addr[:v4start] + '!' # We leave a marker that the address is not finished
		
		# Compact version?
		compact_pos = addr.find('::')
		if compact_pos >= 0:
			if compact_pos == 0:
				addr = '0' + addr
				compact_pos += 1
			if compact_pos == len(addr)-len('::'):
				addr = addr + '0'
			
			addr = (addr[:compact_pos] + ':' +
				('0:' * (wordcount - (addr.count(':') - '::'.count(':')) - 2))
				+ addr[compact_pos + len('::'):])
		
		# Remove any dots we left
		if addr.endswith('!'):
			addr = addr[:-len('!')]
		
		words = addr.split(':')
		if len(words) != wordcount:
			raise ValueError('Invalid number of IPv6 hextets, expected ' + str(wordcount) + ', got ' + str(len(words)))
		for w in reversed(words):
			# 0x and negative is not valid here, but accepted by int(,16)
			if 'x' in w or '-' in w:
				raise ValueError("Invalid character in IPv6 address")
			
			intval = int(w, 16)
			if intval > 0xffff:
				raise ValueError("IPv6 address componenent too big")
			res = struct.pack('!H', intval) + res
		
		return res
		
	else:
		raise ValueError("Unknown protocol family " + family)

# Cover for socket_pton inavailability on some systems (non-IPv6 or Windows)
try:
	import ipaddr
	
	if hasattr(ipaddr.IPv4, 'packed'):
		def _inet_pton(family, addr):
			if family == socket.AF_INET:
				return ipaddr.IPv4(addr).packed
			elif family == socket.AF_INET6:
				return ipaddr.IPv6(addr).packed
			else:
				raise ValueError("Unknown protocol family " + family)
except:
	pass

if not '_inet_pton' in dir():
	if hasattr(socket, 'inet_pton'):
		_inet_pton = socket.inet_pton
	else:
		_inet_pton = _compat_inet_pton

if __name__ == "__main__":
	_main()
