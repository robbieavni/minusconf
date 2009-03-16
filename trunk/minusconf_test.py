#!/usr/bin/env python
"""Apache License 2.0, see the LICENSE file for details."""

import unittest
import minusconf
import socket
import time

class MinusconfUnitTest(unittest.TestCase):
	def setUp(self):
		sharp_s = chr(223)
		self.svc1 = minusconf.Service('-conf-test-service', 'strangeport', 'some name')
		self.svc2 = minusconf.Service('-conf-test-service' + sharp_s, 'strangeport', 'some name')
		self.svc3 = minusconf.Service('-conf-test-service' + sharp_s, 'svcp3', 'svc3: sharp s = ' + sharp_s)
		self.svc4 = minusconf.Service('-conf-test-service' + sharp_s, 'svcp4', 'svc4')
	
	def testServiceMatching(self):
		a = minusconf.Advertiser()
		def assert_sm(stype, sname, expected):
			self.assertEquals(set(a.services_matching(stype, sname)), set(expected))
		
		assert_sm('', '', [])
		
		a.services.append(self.svc1)
		assert_sm(self.svc1.stype, self.svc1.sname, [self.svc1])
		assert_sm(self.svc1.stype, '', [self.svc1])
		
		a.services.append(self.svc2)
		assert_sm(self.svc2.stype, self.svc2.sname, [self.svc2])
		
		a.services.append(self.svc3)
		assert_sm(self.svc3.stype, self.svc3.sname, [self.svc3])
		assert_sm('', self.svc3.sname, [self.svc3])
		
		assert_sm('', '', [self.svc1, self.svc2, self.svc3])
	
	def testServiceRepresentation(self):
		for reprfunc in (repr,str):
			for svc in [self.svc1, self.svc2, self.svc3, self.svc4, minusconf.ServiceAt('a', 'b', 'c', 'd', 'e', 'f')]:
				r = reprfunc(svc)
				self.assertTrue(r.find(svc.stype) >= 0)
				self.assertTrue(r.find(svc.port) >= 0)
				self.assertTrue(r.find(svc.sname) >= 0)
	
	def testRealExample(self):
		a1 = minusconf.Advertiser([self.svc1])
		a1.start()
		a2 = minusconf.Advertiser([self.svc3])
		a2.start()
		self.assertEquals(self.svc2.stype, self.svc3.stype)
		self.assertEquals(self.svc2.stype, self.svc4.stype)
		
		a1.services.append(self.svc2)
		a2.services.append(self.svc4)
		
		# Wait for advertisers
		time.sleep(0.5)
		
		s = minusconf.Seeker(self.svc2.stype, timeout=0.5)
		svc_eq = lambda svc, exp: (svc.sname == exp.sname and svc.stype == exp.stype and svc.port == exp.port)
		svc_in = lambda svc, svcs: any((svc_eq(svc, s) for s in svcs))
		s.find_callback = lambda seeker,svcat: self.assertTrue(svc_in(svcat, [self.svc2, self.svc3, self.svc4]))
		s.error_callback = lambda seeker,errorstr: self.fail('Got error ' + repr(errorstr) + ' from ' + repr(seeker))
		
		s.run()
		
		self.assertTrue(not svc_in(self.svc1, s.results))
		self.assertTrue(svc_in(self.svc2, s.results))
		self.assertTrue(svc_in(self.svc3, s.results))
		self.assertTrue(svc_in(self.svc4, s.results))
	
	def testInetPton(self):
		bts = minusconf._compat_bytes
		testVals = [
			(socket.AF_INET, '1.2.3.4', bts('\x01\x02\x03\x04')),
			(socket.AF_INET, '255.254.253.252', bts('\xff\xfe\xfd\xfc')),
			(socket.AF_INET6, '::', bts('\x00')*16),
			(socket.AF_INET6, '::1', bts('\x00')*15 + bts('\x01')),
			(socket.AF_INET6, '100::', bts('\x01') + bts('\x00')*15),
			(socket.AF_INET6, '0100::', bts('\x01') + bts('\x00')*15),
			(socket.AF_INET6, '1000::', bts('\x10') + bts('\x00')*15),
			(socket.AF_INET6, 'ff25::12:2:254.232.3.4', bts('\xff\x25\x00\x00\x00\x00\x00\x00\x00\x12\x00\x02\xfe\xe8\x03\x04')),
			(socket.AF_INET6, 'ffff:2:3:4:ffff::', bts('\xff\xff\x00\x02\x00\x03\x00\x04\xff\xff') + bts('\x00') * 6),
			]
		
		invalidVals = [
			(socket.AF_INET, '1.2.3'),
        		(socket.AF_INET, '1.2.3.4.5'),
			(socket.AF_INET, '301.2.2.2'),
			(socket.AF_INET, '::1.2.2.2'),
			(socket.AF_INET6, '1:2:3:4:5:6:7'),
			(socket.AF_INET6, '1:2:3:4:5:6:7:'),
			(socket.AF_INET6, ':2:3:4:5:6:7:8'),
			(socket.AF_INET6, '1:2:3:4:5:6:7:8:9'),
			(socket.AF_INET6, '1:2:3:4:5:6:7:8:'),
			(socket.AF_INET6, '1::3:4:5:6::8'),
			(socket.AF_INET6, 'a:'),
			(socket.AF_INET6, ':'),
			(socket.AF_INET6, ':::'),
			(socket.AF_INET6, '::a:'),
			(socket.AF_INET6, ':a::'),
			(socket.AF_INET6, '1ffff::'),
			(socket.AF_INET6, '0xa::'),
			(socket.AF_INET6, '1:2:3:4:5:6:300.2.3.4'),
			(socket.AF_INET6, '1:2:3:4:5:6:1a.2.3.4'),
			(socket.AF_INET6, '1:2:3:4:5:1.2.3.4:8'),
			]
		
		for ptonf in (minusconf._inet_pton, minusconf._compat_inet_pton):
			for (family, arg, expected) in testVals:
				self.assertEquals(ptonf(family, arg), expected)
			
			for (family, arg) in invalidVals:
				self.assertRaises((ValueError, socket.error), ptonf, family, arg)

if __name__ == '__main__':
	unittest.main()
