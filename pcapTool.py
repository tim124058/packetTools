#!/usr/bin/env python3
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy_http.http import *

class packetTools():
    # 回傳所有ip
    @staticmethod
    def getPcapIP(filename):
        pks = rdpcap(filename)
        ips = set()
        for i in pks:
            if i.haslayer(IP):
                ips.update({i[IP].dst,i[IP].src})
        return ips

    # 回傳所有dns response中的domain name
    @staticmethod
    def getPcapDNS(filename):
        pks = rdpcap(filename)
        dns = []
        for i in pks:
            if i.haslayer(DNS):
                for j in range(i[DNS].ancount):
                    rrname = i[DNSRR][j].rrname
                    rrname = rrname.decode()[:-1] if isinstance(rrname,bytes) else rrname
                    rdata = i[DNSRR][j].rdata
                    rdata = rdata.decode()[:-1] if isinstance(rdata,bytes) else rdata
                    dns.append((rrname,rdata))
        return dns
    # 只回傳dns response中的rrname
    @staticmethod
    def getPcapDNSrrname(filename):
        rrnames = set()
        for i,j in packetTools.getPcapDNS(filename):
            rrnames.update({i})
        return rrnames

    @staticmethod
    def sortIP(ips):
        return sorted(ips ,key=lambda x:tuple(map(int,x.split("."))))

    @staticmethod
    def ipCompare(l1,l2):
        return list(set(l1) & set(l2))

    @staticmethod
    def getHTTPRedirect(filename):
        pks = rdpcap(filename)
        redirect = []
        for i,pk in enumerate(pks):
            if pk.haslayer(HTTPResponse):
                t = pk[HTTPResponse].fields.get("Location")
                if t:
                    for j in range(i-1,-1,-1):
                        if (pks[j].haslayer(HTTPRequest) and (pk[IP].dst == pks[j][IP].src and pk[IP].src == pks[j][IP].dst)):
                            src = pks[j][HTTPRequest].Host.decode()
                            break
                    dst = t.decode().split("/")[2]    # only host
                    redirect.append((src,dst))
        return redirect
                    



    # 查詢ip的domain name(reverse ip)
    @staticmethod
    def getHostByAddr(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None


class Main():
    def __init__(self):
        self.setArgs()
        self.outPcapIP()
        self.outPcapDNS()
        self.outPcapDN()
        self.outMatchIP()
        self.outMatchDN()
        self.outRedirect()

    def output(self,s):
        if self.args.o:
            self.args.o.write(s + "\n")
        else:
            print(s)

    def setArgs(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-v", "--verbose", help="顯示詳細資料", action="store_true")
        parser.add_argument("-ip", help="讀取pcap檔，並輸出所有IP", type=argparse.FileType('r'), metavar="file")
        parser.add_argument("-dns", help="讀取pcap檔，並輸出所有dns請求(-v顯示詳細資訊)", type=argparse.FileType('r'), metavar="file")
        parser.add_argument("--domain-name", 
                help="讀取pcap檔，並輸出所有ip的hostname和dns請求", 
                type=argparse.FileType('r'), metavar="file")
        parser.add_argument("--ip-compare", 
                help="比較f1和f2中一樣的ip，f1、f2可為pcap檔或ip文字檔",
                nargs=2,
                type=argparse.FileType('r'),
                metavar=("f1","f2"))
        parser.add_argument("--dn-compare", 
                help="比較f1和f2中一樣的ip，f1、f2可為pcap檔或domain name文字檔",
                nargs=2,
                type=argparse.FileType('r'),
                metavar=("f1","f2"))
        parser.add_argument("--redirect", help="讀取pcap檔，並輸出所有HTTP redirect", type=argparse.FileType('r'), metavar="file")
        parser.add_argument("-o", help="輸出到檔案", type=argparse.FileType('w'), metavar="output_file")
        self.args = parser.parse_args()

    # 以plaintext輸出所有IP
    def outPcapIP(self):
        if self.args.ip:
            ips = self.getFileIP(self.args.ip)
            ips = packetTools.sortIP(ips)
            for i in ips:
                self.output(i)

    # 輸出dns response
    def outPcapDNS(self):
        if self.args.dns:
            try:
                tmp = []
                for i,j in packetTools.getPcapDNS(self.args.dns.name):
                    if self.args.verbose:
                        self.output("%s <-> %s" % (i,j))
                    else:
                        if i not in tmp:
                            self.output(i)
                            tmp.append(i)
            except:
                print("ERROR : 必須為pcap檔")
                exit(1)

    # 以plaintext輸出所有domain name
    def outPcapDN(self):
        if self.args.domain_name:
            dns = self.getFileDN(self.args.domain_name)
            for i in dns:
                self.output(i)

    # 從pcap檔或ip文字檔，取得IP陣列(str)
    def getFileIP(self,file):
        try:
            ips = packetTools.getPcapIP(file.name)
        except:
            ips = file.read().split()
            ips = filter(None,ips)
        return ips
    # 從pcap檔或domain name文字檔，取得domain name陣列(str)
    def getFileDN(self,file):
        try:
            ips = packetTools.getPcapIP(file.name)
            ips = packetTools.sortIP(ips)
            dns = set()
            for i in ips:
                dn = packetTools.getHostByAddr(i)
                if not dn:
                    continue
                dns.update({dn})
            dns.update(packetTools.getPcapDNSrrname(file.name))
            dns = list(dns)
        except:
            dns = file.read().split()
            dns = filter(None,dns)
        return dns



    # 2個檔案中相同的ip
    def outMatchIP(self):
        if self.args.ip_compare:
            ips1 = self.getFileIP(self.args.ip_compare[0])
            ips2 = self.getFileIP(self.args.ip_compare[1])
            match = packetTools.ipCompare(ips1,ips2)
            match = packetTools.sortIP(match)
            if not match:
                print("沒有一樣的ip!")
            else:
                for i in match:
                    self.output(i)

    # 2個檔案中相同的domain name
    def outMatchDN(self):
        if self.args.dn_compare:
            dns1 = self.getFileDN(self.args.dn_compare[0])
            dns2 = self.getFileDN(self.args.dn_compare[1])
            match = packetTools.ipCompare(dns1,dns2)
            if not match:
                print("沒有一樣的domain name!")
            else:
                for i in match:
                    self.output(i)

    # HTTP重新導向
    def outRedirect(self):
        if self.args.redirect:
            redirects = packetTools.getHTTPRedirect(self.args.redirect.name)
            for s,d in redirects:
                self.output("%s -> %s" % (s,d))


if __name__ == "__main__":
    Main()
