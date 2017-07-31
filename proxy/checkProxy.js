// 校验http、https 代理是否可用
// node checkProxy.js ~/C/ip_log.txt 
var fs  = require("fs"),
	a = process.argv.splice(2),
    request = require("request"),
    g_oR = request;


function fnCheck(a)
{
	var aI = a || fs.readFileSync(a[0]).toString().trim().split(/\n/);
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
			(function(t1,reP){
				try{
					r.get(
						{
							uri:"http://erp.yinhai.com:8070/ixp/ip.jsp?me=ok",
							"timeout":5000
						},
					function(e,r,b)
					{
						if(!e && b && /\d+\.\d+\.\d+\.\d+/.test(b = b.trim()))
						{
							console.log("Ok: " + b + "  秒:" + (new Date().getTime() - t1) / 1000);
							// 
							
							g_oR = reP;
						}
					});
				}catch(e1){};
			})(new Date().getTime(), r);
		}
	}
}

// http://www.ip181.com/
// http://www.ip181.com/daili/1.html
// https.globalAgent.options
// https.globalAgent.options
function fnCrawler(url)
{
	var a, aT = [], re = /<td>(\d+\.\d+\.\d+\.\d+)<\/td>\s*<td>(\d+)<\/td>\s*<td>[^<]*<\/td>\s*<td>([^<]+)<\/td>/gmi;
	g_oR//.defaults({'proxy': 'http://127.0.0.1:8080'})
	.get(url,function(e,r,b)
	{
		while(a = re.exec(e || b))
		{
			aT.push(["",a[1],a[2],a[3]].join("|"))
		}
		fnCheck(aT);
	});
}

fnCrawler("http://www.ip181.com/daili/1.html"
	// "http://www.ip181.com/"
	);
