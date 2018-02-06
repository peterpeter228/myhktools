// 数据拷贝
global.copyO2O=function (oS,oD,b)
{
	var o = b? {} : oD;
	if(b)
	{
		for(var k in oD)
		{
			o[k] = oD[k];
		}
	}
	for(var k in oS)
	{
		o[k] = oS[k];
	}
	return o;
}
// 定义全局变量
copyO2O({szMyName:'M.T.X._2017-06-08 1.0',
	program:require('commander'),
	request:require('request'),
	g_oRstAll:{},// 结果差分比较
	args:process.argv.splice(2),
	_request:require('request'),
	urlObj:require('url'),
	g_szSplit:/[,;\s\|]/gmi,
	g_host2Ip:{},// 域名到ip转换缓存
	async:require('async'),
	g_nThread:5,// 并发线程数
	g_szUa:"Mozilla/5.0 (Linux; Android 5.1.1; OPPO A33 Build/LMY47V; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043409 Safari/537.36 V1_AND_SQ_7.1.8_718_YYB_D PA QQ/7.1.8.3240 NetType/4G WebP/0.3.0 Pixel/540",
	child_process:require("child_process"),
	net:require('net'),
	crypto:require('crypto'),
	path:require("path"),
	fs:require('fs'),
	http:require("http"),
	iconv:require("iconv-lite"),
	fnError:function(e)
	{
		console.log(String(e));
	},
	fnMyHelp:function(fn)
{
	var s = (fn||fnHelp).toString().split(/\n/).slice(2, -2).join('\n');
	if(fn)return s
	console.log(s);
},
// 循环处理本地文件、目录
doFile:function(opt)
{
	var filename = opt.filename || ".",filter = opt.filter || function(s)
	{
		return /\.(txt|log|csv|hta|htm|html)/gmi.test(s);
	},delFilter = opt.delFilter || function(s)
	{
		return /\.DS_Store$/gmi.test(s);
	},fnCbk = opt.fnCbk || function(s){};
	fs.stat(filename,function(e,stats)
	{
		if(stats.isFile() && filter(filename) && fs.existsSync(filename))
		{
			try{
				fnCbk(filename);
				/*
				var k = fs.readFileSync(filename);
				fs.writeFileSync(filename,k);
				console.log(filename);
				console.log(k);*/
			}catch(e1){console.log(e1);}
		}
		else if(stats.isDirectory())
		{
			fs.readdir(filename,opt.options || {"encoding":"utf8"},function(e,aF)
			{
				aF.forEach(function(i)
				{
					if(delFilter(i))
					{
						fs.unlinkSync(filename + "/" + i);
					}
					else doFile(copyO2O({filename:filename + "/" + i},opt,true));
				});
			});
		}
	});
}
},global);

// 加载所有的插件动态库
// 各种插件库分开编写，便于维护
// eval(fs.readFileSync(a[k])+'');
process.title = '巅狼团队_M.T.X.V 2.0'
process.stdin.setEncoding('utf8');
process.env.NODE_ENV = "production";
process.on('uncaughtException', fnError);
process.on('unhandledRejection', fnError);

String.prototype.trim=function()
{
	return this.replace(/(^\s*)|(\s*$)/gmi,'');
};

Array.prototype.indexOf=function(s)
{
	for(var k in this)
	{
		if(s == this[k])return k;
	}
	return -1;
};