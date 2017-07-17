# packetTools


### 安裝
```
$ wget https://raw.githubusercontent.com/tim124058/packetTools/master/pcapTool.py
```

### 相關套件安裝
scapy :  

```
$ sudo pip3 install scapy-python3
```

scapy-http :   

```
$ git clone https://github.com/invernizzi/scapy-http.git
$ cd scapy-http
$ sudo python3 setup.py install
```


### 使用

```
usage: pcapTool.py [-h] [-v] [-ip file] [-dns file] [--domain-name file]
                   [--ip-compare f1 f2] [--dn-compare f1 f2] [--redirect file]
                   [-o output_file]

optional arguments:
  -h, --help          show this help message and exit
  -v, --verbose       顯示詳細資料
  -ip file            讀取pcap檔，並輸出所有IP
  -dns file           讀取pcap檔，並輸出所有dns請求(-v顯示詳細資訊)
  --domain-name file  讀取pcap檔，並輸出所有ip的hostname和dns請求
  --ip-compare f1 f2  比較f1和f2中一樣的ip，f1、f2可為pcap檔或ip文字檔
  --dn-compare f1 f2  比較f1和f2中一樣的ip，f1、f2可為pcap檔或domain name文字檔
  --redirect file     讀取pcap檔，並輸出所有HTTP redirect
  -o output_file      輸出到檔案
```
