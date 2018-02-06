#! /usr/bin/env python
#!coding=utf-8
__author__ = 'M.T.X.'
'''
1、获得请求者的mac地址
'''
from scapy.all import *
import pickle
import os
import datetime
import atexit
import netifaces

fileName = "myMacData.txt"
g_data = {}
g_IPdata = {}
g_szGateway = ''
g_szGatewayMac = ''

def writeData(data):
    f = open(fileName, 'wb');
    pickle.dump(data, f)
    f.close()
    return
# 加载数据
def LoadData():
    if not os.path.exists(fileName):
        return {}
    f = open(fileName, 'rb');
    data = pickle.load(f)
    g_data = data
    f.close()
    return data

def myExit():
    writeData(g_data)
    print "成功保存数据"
atexit.register(myExit)

# 时间戳
def nowTm():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def doPack(pkt):
    # data = str(pkt[TCP].sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    # .decode("utf8",errors='ignore')
    data = str(pkt)
    
    # print data
    if pkt[IP].dst == '192.168.24.15' and -1 < data.find("GET ") and -1 < data.find("HTTP/1.1") and -1 < data.find("User-Agent"):
        data = str(pkt.load)
        print [pkt.src,pkt[IP].src, data]
        # pkt.show()
    else:# if pkt[IP].dst != '192.168.24.15' and pkt[IP].src != '192.168.24.15':
        print [pkt.src,pkt[IP].src, pkt.dst,pkt[IP].dst]

def monitor_callback(pkt):
    try:
        doPack(pkt)
    except Exception, e:
        print str(e)
        pass
        #pkt[ARP].show()
        return
def main():
    # os.getenv os.environ.get('HOME','/home/username/')
    os.system('sudo sysctl -w net.inet.ip.forwarding=1 > /dev/null')
    os.system('sudo sysctl -w net.inet.ip.fw.enable=1 > /dev/null ')
    defNet = netifaces.gateways()['default'][netifaces.AF_INET]
    g_szGateway = defNet[0]
    LoadData()
    sniff(prn=monitor_callback, filter="tcp", store=0)

if __name__ == '__main__':
    main()