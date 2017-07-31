// 校验http、https 代理是否可用
// node checkProxy.js ~/C/ip_log.txt 
var fs  = require("fs"),
	a = process.argv.splice(2),
    request = require("request");


var aI = fs.readFileSync(a[0]).toString().trim().split(/\n/);

console.log("Ip数量: " + aI.length);
for(var i = 0; i < aI.length; i++)
{
	if(aI[i] = aI[i].trim())
	{
		var aT = aI[i].split(/\s*\|\s*/);
		
		if(3 > aT.length || !aT[1])continue;
		// console.log("Start: " + aT[1]);
		r = request.defaults({'proxy': aT[3].toLowerCase()+ '://' + aT[1] + ":" + aT[2]});
		process.env[aT[3] + "_PROXY"] = aT[1] + ":" + aT[2];
		// process.env["HTTPS_PROXY"] = ;
		(function(t1){
			try{
				r.get(
					{
						uri:"http://erp.yinhai.com:8070/ixp/ip.jsp?me=ok",
						"timeout":5000
					},
				function(e,r,b)
				{
					if(!e && b)
						console.log("Ok: " + b.trim() + "  秒:" + (new Date().getTime() - t1) / 1000);
				});
			}catch(e1){};
		})(new Date().getTime());
		
	}
}