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

fileName = "myArpData.txt"
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

def findMac(mac):
    cnt = 0
    for ip in g_IPdata:
        if mac == g_IPdata[ip]:
            cnt = cnt + 1 
    return cnt

def findIp(ip):
    if ip in g_IPdata:
        return g_IPdata[ip]
    return ''
# 删除欺骗人的信息记录
def delMac(mac):
    del g_data[mac]
    for k in g_IPdata:
        if g_IPdata[k] == mac:
            del g_IPdata[k]

def pushMacInfo(szMac,ip):
    if '00:00:00:00:00:00' == szMac or 'ff:ff:ff:ff:ff:ff' == szMac or ip == '0.0.0.0':
        return 
    oT = findIp(ip)
    if ('' != oT and szMac != oT) or 1 < findMac(szMac):
        print "发现：" + szMac + " 正在ARP欺骗: " + oT + "(" + ip + ")"
        delMac(szMac)
        return
    g_IPdata[ip] = szMac
    oCurMac = {}
    # 历史数据中如果有就直接取出
    if szMac in g_data:
        oCurMac = g_data[szMac]
    oCurMac["mac"] = szMac
    # 如果当前的ip还没有记录，就记录
    if ip not in oCurMac:
        oCurMac[ip] = {"firstTime": nowTm(),"count":0};
    oCurMac[ip]["lastTm"] = nowTm()
    oCurMac[ip]["count"] = oCurMac[ip]["count"] + 1
    g_data[szMac] = oCurMac
    return oCurMac

def doPack(pkt):
      # 记录第一个有效的网关mac地址
    global g_szGatewayMac
#     global g_data
    if '' == g_szGatewayMac:
        if g_szGateway == pkt[ARP].psrc:
            g_szGatewayMac = pkt[ARP].hwsrc
        if g_szGateway == pkt[ARP].pdst:
            g_szGatewayMac = pkt[ARP].hwdst
    # mac地址
    pushMacInfo(str(pkt[ARP].hwsrc),pkt[ARP].psrc)
    # 目的地址进行记录
    pushMacInfo(str(pkt[ARP].hwdst),pkt[ARP].pdst)
#     pkt.show()

def arp_monitor_callback(pkt):
    try:
        if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
            doPack(pkt)
    except Exception, e:
        print str(e)
        pass
        #pkt[ARP].show()
        return
def main():
    defNet = netifaces.gateways()['default'][netifaces.AF_INET]
    g_szGateway = defNet[0]
    g_data = LoadData()
    sniff(prn=arp_monitor_callback, filter="arp", store=0)

if __name__ == '__main__':
    main()