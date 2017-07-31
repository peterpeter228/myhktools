// 校验http、https 代理是否可用
// node checkProxy.js ~/C/ip_log.txt 
var fs  = require("fs"),
	http = require("http"),
	a = process.argv.splice(2),
    request = require("request"),
    g_aProxy = null,
    nPort = 8080,
    szIp = "0.0.0.0";

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

// 设置代理主程序
function fnCreateProxyServer()
{
	var nTimeout = 5000, server = http.createServer(function (req, resp)
	{
		// 检查通过就回调继续走
		fnSafeCheck(req,function()
		{
			/*
Error: ESOCKETTIMEDOUT
    at ClientRequest.<anonymous> (/Users/xiatian/safe/myhktools/node_modules/request/request.js:819:19)
			*/
			var r = getRequest(),
				x = r({"uri":req.url,"timeout":nTimeout});
			req.pipe(x);
	    	x.pipe(resp);
		});
	});
	server.on('clientError', (err, socket) => {
	  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
	});
	server.on('close', (err) => {
	});
	server.on('connect', (request, socket,headBuffer) => 
	{
		console.log([socket.remoteFamily,socket.remoteAddress,socket.remotePort])
	  // socket.end();
	});
	server.on('request', (request,response) => {
	});
	server.on('upgrade', (request, socket,headBuffer) => {
		//socket.end();
	});
	server.listen(nPort,szIp,function()
	{
		console.log("start: " + szIp + ":" + nPort);
	});
	server.maxHeadersCount = 2000;

	server.setTimeout(nTimeout);
	server.timeout = nTimeout;
	server.keepAliveTimeout = nTimeout;
}

fnCreateProxyServer();