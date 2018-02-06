// svn 弱密码检测 2017-01-22 M.T.X
// node checkSvn.js http://192.168.10.70:8090/svn/ userName Pswd
require('./commonlib/core.js');
var g_bDownload = true,
	g_aDownloadUrls = [];
	reFilter = /(jar|java|exe|cab|jsp|xml|zip|war|ear)$/gmi
	;

/*
生成密码
*/
function fnMkUp (u,p)
{
	var s = new Buffer(u + ":" + p);
	return(s.toString("base64"));
}

/*
检查单个路径
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

// 从序列化文件加载待下载的文件
// 
// 每个序列的url包含状态，{获取时间、用户名、密码、urls:[{url、状态（开始下载、已经下载）}]}
function getUrls(szAddUrls)
{
	// g_aDownloadUrls = ;
	if(szAddUrls)
	{
		g_aDownloadUrls.push(szAddUrls);
		// 写序列化文件
	}
	var fnT = function()
	{
		async.mapLimit(g_aDownloadUrls,133,function(s,fnCbk)
		{
			fnCheckSvn(u + s, user,pswd,function(e,r,b)
			{
				fnCbk();
				if(e)return console.log(e);
				// 创建本地目录
				// 保存文件
				// md5生成和检查
			});
		});
	};
	fnT();
}
// 存储目录
var g_svnDataPath = "./data/svn/";
var indexAll = "data/svn/indexAll.txt", allSvnInfo = g_svnDataPath + 'allSvnInfo.txt',g_oSvnAll = {},g_oSvnInfo = {};
function fnGetHds(resp,o)
{
	var oCurSvn = o,aH = "date,last-modified".split(g_szSplit);
	for(var k in aH)
	{
		if(resp.headers[aH[k]])
			oCurSvn[aH[k]] = resp.headers[aH[k]];
	}
	return o;
}
// 分析目录连接
function fnGetAllUrls(u,p,url,s,resp)
{
	var re = [/svn\s*-\s*Revision\s*\d+:\s+\/([^<]+)</gmi,
	         /<a href="([^"]+)">/gmi],a;
	var oUser = g_oSvnAll[u] || (g_oSvnAll[u] = {}), oCurSvn = null;
	if(a = re[0].exec(s))
	{
		oCurSvn = g_oSvnInfo[a[1]] || (g_oSvnInfo[a[1]] = {});
	}
	fnGetHds(resp,oCurSvn);
	// console.log(resp.headers);
	// console.log(s);
	var aSnvPush = oCurSvn.urls || (oCurSvn.urls = {});
	while(a = re[1].exec(s))
	{
		if(/\.\.\/$/gmi.test(a[1]))continue;
		//*
		if(/\/$/gmi.test(a[1]))
		{
			fnCheckSvn(url + "/" + a[1], u,p,function(e,r,b)
			{
				// fnGetAllUrls(u,p,url,s,resp)
				var oTmp = {};
				oTmp = fnGetHds(r,oTmp);
				aSnvPush[decodeURI(r.req.path)] = oTmp;
				// console.log(r.headers);
				// console.log(r.req.path);
				// console.log(decodeURI(r.req.path));
			});
		}// 单个文件路径的记录
		else
		{
			aSnvPush[decodeURI(resp.req.path + a[1])] = {};
		 	// console.log(url + "/" + a[1]);
		}
		//*/
	}
}

/*
检查并输出
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
			// console.log(r.request.uri.href);// path
			fnCbk();
			if(e)return console.log(e);
			var s1 = String(b).replace(/<.*?>/gmi,'');
			
		 	if(-1 < s1.indexOf("svn - Revision") && -1 == s1.indexOf("You don't have permission to access") && -1 == s1.indexOf("bad password"))
		 	{
		 		if(g_bDownload)fnGetAllUrls(user,pswd,u + s,b,r);
		 		var a9 = [,user,pswd];
		 		var oUser = g_oSvnAll[a9[1]] || (g_oSvnAll[a9[1]] = {}),
		 		    pwd = oUser.pwd || (oUser.pwd = []),
		 		    svns = oUser.svns || (oUser.svns = []);
	 		    if(-1 == svns.indexOf(s))
	 		    	svns.push(s);
		 		if(-1 == pwd.indexOf(pswd))
		 			pwd.push(pswd);
		 		// console.log(oUser);
		 		console.log(["svn checkout",u + s,"--username",user,"--password",pswd].join(" "));
		 		// console.log(["Ok",r.statusCode, s1]);
		 	}
		});
	});
}



function updateSvnIndexAll()
{
	fs.writeFileSync(indexAll,JSON.stringify(g_oSvnAll));
	fs.writeFileSync(allSvnInfo,JSON.stringify(g_oSvnInfo));
	
}

process.on('exit', (code) => 
{
	if(g_bDownload)
	{
		updateSvnIndexAll();
		console.log(g_oSvnInfo);
	}
	else console.log(g_oSvnAll);
	// var ss = JSON.stringify(g_oSvnAll,null,' ');
	// console.log(ss);
	// console.log(g_oSvnAll);
});
// 加载、更新所有用户名及密码
if(g_bDownload)
{
	+function()
	{
		// 1、初始化svn历史信息
		var k = "";
		if(fs.existsSync(indexAll))
		{
			k = fs.readFileSync(indexAll);
			if(k)
			{
				g_oSvnAll = JSON.parse(k);
				console.log("成功加载: " + indexAll);
			}
		}

		if(fs.existsSync(allSvnInfo))
		{
			k = fs.readFileSync(allSvnInfo);
			if(k)
			{
				g_oSvnInfo = JSON.parse(k);
				console.log("成功加载: " + allSvnInfo);
			}
		}
		
		// 2、梳理本地可用信息
		doFile({"filename":"./data",fnCbk:function(s)
		{
			k = fs.readFileSync(s).toString();
			var a,re = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s+\/([^\s\/]+)\/([^\s\/]+)\s+Mozilla/gmi, bHv = false,
			    re1;
			while(a = re.exec(k))
			{
				bHv = true;
				re1 = /\.(git)/gmi;
				try{
					a[1] = decodeURI(a[1]);
					a[2] = decodeURI(a[2]);
				}catch(e){}
				if(!re1.test(a[1]))
				{
					var oUser = g_oSvnAll[a[1]] || (g_oSvnAll[a[1]] = {}),pwd = oUser.pwd || (oUser.pwd = []);
					if(-1 == pwd.indexOf(a[2]))
						pwd.push(a[2]);
					// if(1 < pwd.length) console.log(pwd);
				}
			}
			// if(bHv)console.log(s);
		},filter:function(s)
		{
			return /(192|10)\.\d{1,3}\.\d{1,3}\.\d{1,3}\.txt$/gmi.test(s);	
		}});
		/*//////////检查所有人的svn权限:需要考虑线程问题///////////////
		for(var k in g_oSvnAll)
		{
			var o = g_oSvnAll[k];
			if(o.pwd)
			{
				for(var i = 0; i < o.pwd.length; i++)
				{
					fnCheckAll(process.env.svnUrl,k,o.pwd[i]);
				}
			}
		}
		////////////////////////*/
	}();
}
/*
for(var k in async)
if("function" == typeof async[k])
{
	console.log(k + ":" + async[k].toString());
}*/

if(0 < args.length)fnCheckAll(args[0],args[1],args[2]);