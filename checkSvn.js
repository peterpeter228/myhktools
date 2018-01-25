// svn 弱密码检测 2017-01-22 M.T.X
// node checkSvn.js http://11.112.18.10:8090/svn/ userName Pswd
fs  = require("fs"),
	http = require("http"),
	async = require('async'),
	args = process.argv.splice(2),
	request = require("request");

/*
生成密码
*/
function fnMkUp (u,p)
{
	var s = new Buffer(u + ":" + p);
	return(s.toString("base64"));
}

/*

*/
function fnCheckSvn(url,u,p,fnCbk)
{
	request({method: 'GET',uri:url,headers:
		{
			authorization: 'Basic ' + fnMkUp(u,p).replace(/\s/gmi, ''),
			'user-agent':"Mozilla/5.0 (Linux; Android 5.1.1; OPPO A33 Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043409 Safari/537.36 V1_AND_SQ_7.1.8_718_YYB_D PA QQ/7.1.8.3240 NetType/4G WebP/0.3.0 Pixel/540"//'Mozilla/6.0 (win10; Intel lly 99_88_55) ms/000.4.7 (KHTML, like Gecko) Version/99.0.2 Safari/888.1.5 lly'
		}},function(e,r,b)
	{
		fnCbk(e,r,b);
	});
}

/*
*/
function fnCheckAll(u,user,pswd)
{
	var url = u, a = fs.readFileSync("./urls/yhxm.txt").toString().split(/\n/gmi);
	console.log("检查 " + a.length + "个项目.... ");
	// 并发5个线程 : 5189
	async.mapLimit(a,133,function(s,fnCbk)
	{
		if(0 < (s = s.trim()).length)
		fnCheckSvn(u + s, user,pswd,function(e,r,b)
		{
			fnCbk();
			if(e)return console.log(e);
			var s1 = String(b).replace(/<.*?>/gmi,'');
			
		 	if(-1 < s1.indexOf("svn - Revision") && -1 == s1.indexOf("You don't have permission to access") && -1 == s1.indexOf("bad password"))
		 	{
		 		console.log(["svn checkout",u + s,"--username",user,"--password",pswd].join(" "));
		 		// console.log(["Ok",r.statusCode, s, s1]);
		 	}
		});
	});
}

fnCheckAll(args[0],args[1],args[2]);