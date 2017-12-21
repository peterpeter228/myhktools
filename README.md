本工具以mac os x 10.12.5的环境
# 巅狼安全 团队倾情奉献
# struts2安全检查
自动捕获表单字段并调用相关漏洞进行检测
```
tomcat Put test
Struts2_001
Struts2_005
Struts2_007
Struts2_008
Struts2_009
Struts2_012
Struts2_013
Struts2_015
Struts2_016
Struts2_019
Struts2_020
Struts2_029
Struts2_032
Struts2_033
Struts2_037
Struts2_DevMode
Struts2_045
Struts2_046
Struts2_048
Struts2_053
elasticsearch
伪造host等检测

node checkUrl.js -u url

查看帮助
node checkUrl.js -h
Options:

    -V, --version           output the version number
    -u, --url [value]       check url, no default
    -p, --proxy [value]     http proxy,eg: http://127.0.0.1:8080, or https://127.0.0.1:8080, no default
    -t, --t3                check weblogic t3,default false
    -i, --install           install node modules,run: npm install
    -v, --verbose           show logs
    -w, --struts2 [value]   struts2 type,eg: 045
    -C, --cmd [value]       cmd type,eg: "ping -c 3 www.baidu.com"
    -o, --timeout           default 5000
    -l, --pool              default 100
    -r, --test              test
    -m, --menu [value]      scan url + menus, default ./urls/ta3menu.txt
    -s, --webshell [value]  scan webshell url，设置参数才会运行, default ./urls/webshell.txt
    -d, --method [value]    default PUT,DELETE,OPTIONS,HEAD,PATCH test
    -a, --host              host attack test,设置代理后该项功能可能无法使用,default true
    -k, --keys [value]      scan html keywords, default ./urls/keywords
    -h, --help              output usage information
```

# 反序列化检测
## 1、新建、编辑ip.txt
192.168.10.221:7001
192.168.10.222:7001
## 2、运行
python weblogic.py
当发现问题后，会自动调动jfxl.jar进行验证
但是，最新的漏洞CVE-2017-3248无法验证

# 获取图片中的元数据（经纬度、创建时间）
```
node getFileMetadata.js /your/img/file
```
# 手工XSS、渗透时需要的一些常用编码、解码
strDecodeEncode.html

# 动态代理，每次自动随机使用代理
启动
```
pm2 start ProxyServer.js -i max
```
然后本机代理设置为127.0.0.1  8080
```
验证：http://ip.cn
```
pm2的安装
```
npm install -g pm2
```
更新代理 autoProxy.txt
```
node checkProxy.js
cat autoProxy.txt|sort|uniq >ok.txt
mv ok.txt autoProxy.txt
cat autoProxy.txt|wc -l
```
# 后渗透后得到很多win的数据txt文件，字符集gbk批量转换为utf8
```
node gbk2utf8.js /your/fileOrdir
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
安装组件
npm install -g commander
安装需要的组件
node checkUrl.js -i

....
</code>

# 安装
brew install node
mkdir ~/safe && cd ~/safe
git clone https://github.com/hktalent/weblogic_java_des  mtx_jfxl

myhktools
</pre>
