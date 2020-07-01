仿照metasploit的风格编写的小工具

1 主机发现  主要使用Python的第三方库scapy
2 端口扫描  主要使用python自带库socket  
3 包嗅探    主要使用scapy
4 ARP投毒   scapy
5 zip爆破    python自带库 zipfile
6 爬虫      requests库

由于metasploit采用Ruby编写，而两种语言间有许多特性不同，相同功能实现起来不一样，操作风格类似，命令大部分重合

sniff模块
load加载数据包
display查看数据包

若要实现中间人攻击，需要在本机打开包转发功能，再使用工具过滤包内容，此工具暂无此功能

由于脚本语言的特性，速度稍慢

主机发现和端口扫描害得nmap
包嗅探害得wireshark
中间人攻击可以使用arpspoof
爬虫功能Python有很多框架和库例如selenium，scrapy
以上工具大都集成在kali中
