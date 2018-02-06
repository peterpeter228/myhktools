#! /usr/bin/env python
#!coding=utf-8
__author__ = 'M.T.X.'
'''

'''
from scapy.all import *

sendp(Ether(dst="50:7B:9D:4B:A1:75",src="ff:ff:ff:ff:ff:ff")/IP(dst="127.0.0.1",ttl=(1,4))/"测试数据", iface="en0")
