// 校验http、https 代理是否可用
// node checkProxy.js ~/C/ip_log.txt 
var fs  = require("fs"),
	http = require("http"),
	a = process.argv.splice(2),
    request = require("request"),
    g_aProxy = null,
    nPort = 8080,
    szIp = "0.0.0.0";

process.on('uncaughtException', function(e){});
process.on('unhandledRejection', function(e){});

function fnWathProxyFile(s)
{
	var fnCbk = function()
	{
		if(fs.existsSync(s))
			g_aProxy = fs.readFileSync(s).toString().trim().split(/\n/);
	};
	fnCbk();
	fs.watch(s,{encoding:'buffer'},(eventType, filename)=>
	{
		if (filename)
		{
			fnCbk();
		}
	});
}

// 设置二级代理并返回request对象
function getRequest()
{
	// if(1)return request;
	var szAutoProxyIps = __dirname + "/" + (process.env["autoProxy"] || "autoProxy.txt");
	
	fnWathProxyFile(szAutoProxyIps);
	if(!g_aProxy)return request;

	// 随机获得代理
	// HTTP,ip,port
	var n = parseInt(Math.random() * 2000000000) % g_aProxy.length, aT = g_aProxy[n];
	if("string" == typeof aT)aT = aT.replace(/\s/gmi, "").split(/[,\|]/);
	if(3 > aT.length)return request;
	process.env[aT[0] + "_PROXY"] = aT[1] + ":" + aT[2];
	console.log("当前代理: " + process.env[aT[0] + "_PROXY"]);
	return request.defaults({'proxy': aT[0].toLowerCase()+ '://' + aT[1] + ":" + aT[2]});
}

/* 安全检查：
1、不能访问本机资源
2、黑名单
3、去除广告
/////////////////////*/
function fnSafeCheck(req, fnCbk)
{
	fnCbk();
}

// 请求前对一些信息进行处理
function fnPrevReq(req)
{
	/*
_this["random-agent"] = true;
            var uas = require("./allUserAgents"), szTmpUa = uas[Math.random() * 20000 % uas.length];
            req.headers["user-agent"] = szTmpUa;
	*/
}
var g_oGl = {},g_szSubmit_key = null;

function fnFilterFunc(o,req)
{
	for(var k in o)
	{
		if("function" == typeof o[k])
		{
			(function(f,k)
			{
				// console.log(k);
				if("setHeader" == k)
				{
					o[k] = function()
					{
						// var a = [].slice.call(arguments);
						var a = [];
						for(i = 0; i < arguments.length; i++)
						{
							a[i] = arguments[i];
						}
						// console.log(this.headers["cookies"]);
						// console.log(this);
						
						if("set-cookie" == a[0])
						{
							var re = /JSESSIONID=([^;]+)/gmi.exec(a[1][0]);
							if(re && 0 < re.length)
							{
								this.JSESSIONID = re[1];
								console.log("得到 JSESSIONID: " + this.JSESSIONID);
							}
							
						}
						// _SUBMIT_KEY
						if("_submit_key'" == a[0])
						{
							console.log("得到 响应中_submit_key: " + a[1]);
							// 首次响应
							if(this.JSESSIONID)g_oGl[this.JSESSIONID] = a[1];
							else console.log("响应中_submit_key 无法得到JSESSIONID关联");
							// 请求时获得submit_key 
							if(req.headers)
							{
								var ss = req.headers["cookie"];
								if(ss)
								{
									var re = /JSESSIONID=([^;]+)/gmi.exec(ss)[1];
									if(g_oGl[re])
									{
										console.log("成功获取到: " + g_oGl[re]);
									}
								}
							}
						}
						// console.log(this);
						f.apply(o,a);
					};
				}
			})(o[k],k);
		}
	}
}

var g_oMT = {};
// 设置代理主程序
function fnCreateProxyServer()
{
	var nTimeout = 19000, server = http.createServer(function (req, resp)
	{
		// 检查通过就回调继续走
		// JSESSIONID _SUBMIT_KEY
		fnSafeCheck(req,function()
		{
			/**
			if(req.method == "GET" ||
				|| ("content-length" in req.headers) && 0 == req.headers["content-length"]
				|| ("content-type" in req.headers) && 'text/plain' == req.headers["content-type"]
				)
			//////////////*/
			{
				var r = request,// getRequest(),// 获取动态代理
					x = r[req.method.toLowerCase()]({"uri":req.url,"timeout":nTimeout});
				req.pipe(x);
				// fnFilterFunc(resp);
		    	resp = x.pipe(resp);
	    	}
	    	/*
	    	else 
	    	{
	    		// content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
	    		// console.log(req.method + " "+  req.url);
	    		console.log(req.headers);
	    		var ss = req.headers["cookie"],re;
				if(ss)
				{
					re = /JSESSIONID=([^;]+)/gmi.exec(ss)[1];
				}
	    		req.on("data",function()
	    		{
	    			var s = String(arguments[0]);
	    			console.log("拼接前：" + s);
	    			
	    			if(g_oMT[re] && -1 == s.indexOf('_SUBMIT_KEY=NONE'))
	    				s += "&_SUBMIT_KEY=" + g_oMT[re];
	    			console.log("拼接后：" + s);
	    			
	    			request.post({uri:req.url,"timeout":nTimeout,headers:req.headers,body:s},function(e,r,b)
					{// _SUBMIT_KEY
						delete r.headers['x-powered-by'];delete r.headers['server'];
						// console.log(r.headers);
						if(r.headers && r.headers['_submit_key'])
						{
							console.log("成功获取到: " + r.headers['_submit_key']);
							if(re)g_oMT[re] = r.headers['_submit_key'];
						}
						b = b.trim();
						console.log(b);
						resp.end(b);
					});
	    		});
	    	}////////*/
		});
	});
	server.on('clientError', (err, socket) => 
	{
		if(err)console.log(err);
	  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
	});
	server.on('close', (err) => {
		if(err)console.log(err);
	});
	server.on('connect', (request, socket,headBuffer) => 
	{
		console.log([socket.remoteFamily,socket.remoteAddress,socket.remotePort])
	  // socket.end();
	});
	
	server.on('request', (request,response) => {
		let body = [];
		request.on('data', (chunk) => {
		  body.push(chunk);
		}).on('end', () => {
		  body = Buffer.concat(body);
		  var fs = require("fs");
		  fs.writeFileSync("testAmf.bin",body);
		  console.log(body.toString());
		  // at this point, `body` has the entire request body stored in it as a string
		});
	});
	server.on('upgrade', (request, socket,headBuffer) => {
		//socket.end();
	});
	server.listen(nPort,szIp,function()
	{
		console.log("start: " + szIp + ":" + nPort);
	});
	server.maxHeadersCount = 2000;

	// 超时设置
	server.setTimeout(nTimeout);
	server.timeout = nTimeout;
	server.keepAliveTimeout = nTimeout;
}
// 启动多个
// pm2 start ProxyServer.js -i max
process.setMaxListeners(0);
require('events').EventEmitter.prototype._maxListeners = 0;
require('events').EventEmitter.defaultMaxListeners = 0;
fnCreateProxyServer();
