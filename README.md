# DNS-Client-and-Server-

sudo ./server 127.0.0.2 本地 0
sudo ./server 127.0.0.3 根 1
sudo ./server 127.0.0.4 中国与美国 1
sudo ./server 127.0.0.5 教育.中国 1
sudo ./server 127.0.0.6 政府.美国 1
sudo ./server 127.0.0.7 商业与组织 1

./client 127.0.0.2 主页.北邮.教育.中国 A 视窗.微软.商业 A 我.互联网工程任务组.组织 A 大使馆.政府.美国 A 西土城.教育.中国 CNAME 北邮.教育.中国 MX

## Development Environment:
1. Windows 10
2. Oracle VirtualBox with Linux Ubuntu
3. Client VM and server VM
4. Xshell session for DHCP client and server                                          
5. C language
6. gcc compiler and gdb debug tool 

## Functional requirements in details 
1)	Supported Resource Record types: A, MX, CNAME; For MX type queries, the corresponding IP address is required to be carried in Additional Section.
2)	Supported parsing methods: iterative resolution
3)	Support cache, print query trace records (query path, server response time).
4)	Transport layer protocol: client and local DNS server: TCP; DNS servers: UDP.
5)	Application layer protocol: DNS
6)	All DNS messages required to use the communication process must be correctly parsed by wireshark.
7)	The data maintenance of the server can implemented by file.
Extra requirements:
1)	Supported PTR type: Resource Record.
2)	Support to recursive resolution.
3)	Support that one DNS server can carry multiple Query Questions.

