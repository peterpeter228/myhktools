// svn 弱密码检测 2017-01-22 M.T.X
// node checkSvn.js http://118.112.188.108:8090/svn/ userName Pswd
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
http://118.112.188.108:8090/svn/
*/
function fnCheckSvn(url,u,p,fnCbk)
{
	request({method: 'GET',uri:url,headers:
		{
			authorization: 'Basic ' + fnMkUp(u,p).replace(/\s/gmi, ''),
			'user-agent':'Mozilla/6.0 (win10; Intel lly 99_88_55) ms/000.4.7 (KHTML, like Gecko) Version/99.0.2 Safari/888.1.5 lly'
		}},function(e,r,b)
	{
		fnCbk(e,r,b);
	});
}

/*
svn
*/
function fnCheckAll(u,user,pswd)
{
	var url = u, a = fs.readFileSync("./urls/yhxm.txt").toString().split(/\n/gmi);
	console.log("检查 " + a.length + "个项目.... ");
	// 并发5个线程 : 5189
	async.mapLimit(a,5,function(s,fnCbk)
	{
		if(0 < (s = s.trim()).length)
		fnCheckSvn(u + s, user,pswd,function(e,r,b)
		{
			fnCbk();
			if(e)return console.log(e);
		 	if(-1 == String(b).indexOf("You don't have permission to access"))
		 		console.log(["Ok",r.statusCode, s, String(b).replace(/<.*?>/gmi, '')]);
		});
	});
}

fnCheckAll(args[0],args[1],args[2]);