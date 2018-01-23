
module.exports={
	tags:"t3,weblogic",// 驱动监测到这里的关键词，都调用该插件进行检测
	des:"T3开放状态监测",
	suport:"建议关闭T3协议，或者限定特定ip可访问",
// check weblogic T3
// sort ip.txt|uniq>ip2.txt;mv ip2.txt ip.txt
	doCheck:function (url,fnCbk)
	{
		var oU = parseUrl(url),
			h = oU.hostname,p = oU.port || 80,_t = this,
			s = "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n";
		// var s  = "t3 12.1.2\nAS:2048\nHL:19\n\n";
		fnSocket(h,p,s,function(data)
		{
			data=(data||"").toString().trim();
			var r = {"url":url,"send":s};
			if(data && -1 == data.indexOf("Bad Request") && -1 < data.indexOf("10.3."))
			{
				global.copyO2O({"data":data,des:"建议关闭T3协议，或者限定特定ip可访问","vul":true},r);
				console.log("found T3 " + h + ":" + p);
			}
			fnCbk(r,_t);
		});
	}
};