本工具以mac os x 10.12.5的环境
# 动态代理，每次自动随机使用代理
= 启动
```
pm2 start ProxyServer.js -i max
```
= 然后本机代理设置为127.0.0.1  8080
```
验证：curl -x http://127.0.0.1:8080 http://erp.yinhai.com:8070/ixp/ip.jsp?me=ok
```
= pm2的安装
```
npm install -g pm2
```
= 更新代理 autoProxy.txt
```
node checkProxy.js
cat autoProxy.txt|sort|uniq >ok.txt
mv ok.txt autoProxy.txt
cat autoProxy.txt|wc -l
```
# 后渗透后得到很多win的数据txt文件，字符集gbk批量转换为utf8
```
node gbk2utf8.js /your/dir
```
# 多种解码
```
node decode.js base64等格式字符串
```
# 被入侵后，查看整个目录中所有ip信息，包含bin，可自行文件中的ip信息
```
node getIps.js /your/dir
```
# 某种js压缩后的解码、压缩编码
``` 
win下运行
压缩.hta
```

# 某黑客游戏网站获取邀请码
``` 
node getInviteCode.js
``` 
# 连接http隧道
``` 
python reGeorgSocksProxy.py -l 127.0.0.1 -p 8080 -u http://118.222.100.108:8070/ip/x.jsp
``` 
# 一些常用的防火墙，禁ping、nmap
``` 
iptablesSh.sh
iptablesSh.sh
``` 


# 依赖
<pre>
<code>

$ node -v
v8.1.2
$ls -ld /usr/local/lib/node_modules/* | awk '{print $9}'|sed -e 's/\/usr\/local\/lib\/node_modules\///g'
AntColony
Buffer
CSSselect
CSSwhat
anyproxy
archiver
arp
async
async-task-mgr
attack
axon
baidu-ocr-api
basic-auth
bcrypt-nodejs
benchmark
bencode
bignumber.js
bitfield
bittorrent-dht
bittorrent-protocol
bittorrent-tracker
bloom-filter-cpp
body-parser
bookshelf
bower
browserify
buffer-equal-constant-time
bufferhelper
cassandra-driver
caw
change-case
charset
cheerio
child_process
chokidar
cloc
cluster
coap
colorful
colors
commander
compression
connect
consolidate
content-type
cookie-parser
cookie-session
core-util-is
crawler
cron
crypto
csp
css-select
css-what
csurf
csv-parser
csv-stream
cvss3
d3
d3-shape
dateformat
dbx
debug
decompress
deepmerge
depcheck
dgram
dht.js
dhtspider
dnscache
docxtemplater
ejs
encoding
esformatter
eventproxy
excel-export
excel-parser
excel-stream
exif
exifdata
express
express-generator
express-limiter
express-session
fast
forever
formidable
fs
fstream
geoip-lite
getmac
gkt
global-tunnel
gm
google
google-search
gps-util
graceful-fs
grunt
grunt-cli
grunt-retire
gulp-nsp
h2
hashset-cpp
hbase
hbase-client
helmet
helmet-csp
highcharts
hipache
honeypot
html-entities
http
http-proxy
http-proxy-agent
http-proxy-middleware
http-server
https
iconv
iconv-lite
images
inherits
integrity
internal
ip
isarray
iwebpp.io
jake
jdbc
jquery
jschardet
jsdom
jsqr
jszip
jugglingdb
juicer
kademlia
klass
knex
lazy-line-painter
level
leveldown
levelup
lib-qqwry
libpcap
livepool
lodash
log4js
lusca
magnet-uri
mailx
mariasql
md5
microtime
middle-man
mime
mime-types
mocha
module
moment
mongodb
mongoose
mongoskin
morgan
msfnode
mssql
mstsc.js
mtxapp
multiparty
mysql
nano
nedb
needle
net-snmp
nexe
node-dev
node-easy-cert
node-gyp
node-inspector
node-libnmap
node-native-zip
node-raphael
node-rdpjs
node-rsa
node-spider
node-tesseract
node-uuid
node-wifi-scanner
node-xlrd
node-xlsx
node-xmpp-client
node-xmpp-server
node-zip
nodeDHT
nodemailer
npm
npm-check
npm-proxy-cache
npm-registry-client
npmlog
nsp
ocrad.js
open
opencv
owasp-nodejs-goat
p2pspider
pako
path
pdfkit
pg
pg-promise
phantomjs
pica
piexifjs
pm2
poplib
postgresql
promise
protobufjs
protocol-buffers
proxy-tamper
pug
qr-image
qrcode-npm
querystring
raphael
read-config
readable-stream
readline
redis
referrer-policy
replacestream
request
requiresafe
retire
rimraf
serve-favicon
sha1
shadowsocks
sharp
shodan
shodan-client
slickgrid
smb2
snyk
soap
socket.io
sockjs
socksv5
spider
sqlite3
sqlstring
ssh2
ssh2-sftp-client
stream
stream-throttle
string_decoder
strongloop
subcommand
superagent
superagent-charset
superagent-proxy
svg
svg-sprite
svg.js
svgo
svgpath
svn
svn-spawn
svn-utils
swig
tagg
tamper
tar
tedious
term.js
tesseract-ocr
tesseract.js
tessocr
tfidf
thinkjs
tile-lnglat-transform
tor
torrent
toxy
tunnel
underscore
uniq
unzip
url
useragent
ut_metadata
util
uuid
validator
vivus
vm
web
webtorrent
webtorrent-cli
webtorrent-desktop
where-am-i
winston
wreck
ws
xlsx
xmldom
xmlrpc
zaproxy
zip
</code>

# 安装
brew install node
mkdir ~/safe && cd ~/safe
git clone https://github.com/hktalent/weblogic_java_des  mtx_jfxl

myhktools
</pre>
