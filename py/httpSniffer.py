#! /usr/bin/env python
#!coding=utf-8
__author__ = 'M.T.X.'
'''
1、发现当前网络中进行ARP欺骗
2、保护自己免受ARP欺骗
3、发现DNS欺骗
4、保护面搜DNS欺骗
5、发现Sniffer
'''
from scapy.all import *
import pickle
import os
import datetime
import atexit
import netifaces

fileName = "myHttpData.txt"
g_data = {}
g_IPdata = {}
g_szGateway = ''
g_szGatewayMac = ''

def writeData(data):
    f = open(fileName, 'wb');
    pickle.dump(data, f)
    f.close()
    return
def myExit():
    writeData(g_data)
    print "成功保存数据"
atexit.register(myExit)

def LoadData():
    if not os.path.exists(fileName):
        return {}
    f = open(fileName, 'rb');
    data = pickle.load(f)
    f.close()
    for k in data:
        oT = data[k]
        for i in oT:
            g_IPdata[i] = k
    print g_IPdata
    for k in data:
        oT = data[k]
        for i in oT:
            if i == g_szGateway:
                g_szGatewayMac = k
                print "历史网关信息：" + i + " " + k
                return data
    return data

def nowTm():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

'''
###[ Ethernet ]###
  dst       = 32:00:17:ff:a0:00
  src       = 84:5b:12:4a:bc:3a
###[ IP ]###
     src       = 119.23.56.198
     dst       = 192.168.24.10
###[ TCP ]###
        sport     = 36254
        dport     = 62073
'''
def doPack(pkt):
    #if pkt.scr <> '192.168.24.10' and pkt.dst <> '192.168.24.10':
    pkt.show()
    
#     pkt.show()

def arp_monitor_callback(pkt):
    try:
        # if TCP in pkt:
        doPack(pkt)
    except Exception, e:
        # print str(e)
        pass
        #pkt[ARP].show()
        return
def main():
    os.system('sysctl -w net.inet.ip.forwarding=1 > /dev/null')
    # os.system('sudo sysctl -w net.inet.ip.fw.enable=1 > /dev/null ')
    defNet = netifaces.gateways()['default'][netifaces.AF_INET]
    g_szGateway = defNet[0]
    # g_data = LoadData()
    sniff(iface='en1',prn=arp_monitor_callback, filter="ip", store=0)

if __name__ == '__main__':
    main()