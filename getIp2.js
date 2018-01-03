var fs = require("fs"),
	child_process = require("child_process"),
	request = require('request'), szPath = "gsww/";

function fnGetIp(s,fnCbk)
{
	var ip = "host " + s + " | grep 'has address'";
	var szOld = s,s1;
	if(!(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gim.test(s)))
	{
		var szStr = '', k = "has address";
		try{
			szStr = child_process.execSync(ip).toString();
		}catch(e)
		{
			console.log(ip)
			// console.log(e)
			return;
		}
		if(szStr)
		{
			// 多ip兼容
			var aT = szStr.replace(/(^\s*)|(\s*$)/gmi,'').split("\n");
			for(var i = 0; i < aT.length; i++)
			{
				if(-1 < szStr.indexOf(k))
				{
					s = aT[i].split(k)[1].replace(/\s/gmi,'');
					if(1 < aT.length)fnGetIp(s,fnCbk);
				}
			}
			if(1 < aT.length)return;
		}
		else console.log(szStr);
	}
	if(fs.existsSync(s1 = szPath + s))
	{
		fnCbk(JSON.parse(fs.readFileSync(s1).toString()));
		return;
	}
	request.get("http://ipinfo.io/" + s,function(e,r,b)
	{
		if(e)return console.log(e);
		if(-1 < b.indexOf("Wrong ip"))
		{
			console.log(s + "\n" + b);
			return;
		}
		fs.writeFileSync(szPath + szOld,b);
		if(s != szOld)
			fs.writeFileSync(szPath + s,b);
		fnCbk(JSON.parse(b));
	});
}

var a = fs.readFileSync(szPath + "ww.txt").toString().split("\n"),g_oT = {};
for(var i = 0; i < a.length; i++)
{
	var szOld = a[i];
	a[i] = a[i].replace(/(^.*?\/\/)|(:.*?$)|(\/.*?$)|(\s)/gmi, '');
	if("http" == a[i])
		console.log(szOld);
	if(a[i] && !g_oT[a[i]])
	{
		g_oT[a[i]] = 1;
		// console.log(a[i])
		fnGetIp(a[i],function(s)
		{
			// console.log(s);
		});
	}
}