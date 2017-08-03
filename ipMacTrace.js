var express = require('express'),
    fs  = require("fs"), 
    mypath = "./db/", 
    D3Node = require('d3-node'),
    child_process = require('child_process'),
    path = require('path'),
    logger = require('morgan'),
    compress = require('compression'),
    xpb = 'x-powered-by',
    uuid  = require('node-uuid'),
    moment = require('moment'),
    helmet = require('helmet'),
    app = express();

// gzip压缩数据
app.use(compress(
{
  "level":9,
  "memLevel":9,
  // "strategy":// 
  "filter":function(req,res)
  {
      var s = String(res && res.getHeader('Content-Type') || "");
      if(0 == s.indexOf("text/"))return true;
      return compress.filter(req, res);
  }
}));
// 禁止x-powered-by
app.disable(xpb);
// 处理反馈的安全规则不正确的情况
app.post("/rptv",function(req,res)
{
  // if (req.body)console.log(req.body);
  // res.status(204).end();
  res.end();
});
// 对各种未知请求进行处理
app.use(function (req, res, next)
{
  if(!res.locals.nonce)res.locals.nonce = uuid.v4();
  next();
});

app.use(helmet({"noCache":true,"policy":"no-referrer"}));  // 安全头信息处理
app.use(helmet.contentSecurityPolicy({
  directives: {
    "defaultSrc": ["'self'"],
    "imgSrc":["'self'",'data:'],
    "scriptSrc": [
        "'self'",
        "'unsafe-eval'",
        function (req, res)
        {
            return "'nonce-" + res.locals.nonce + "'"
        },
        "'unsafe-inline'"
    ],
    "styleSrc": ["'self'","'unsafe-inline'"],
    "sandbox":['allow-forms', 'allow-scripts','allow-modals'],
    "reportUri": '/rptv'// report-violation
  },
  // "reportOnly": true,
  "browserSniff":true,
  "setAllHeaders":false,
  "disableAndroid": true
}));

function isExists(t)
{
  return fs.existsSync( mypath+ t);
}

// 获取请求者ip信息，并保存起来
function getIp(req)
{
  try{
    var ip = String(req.connection.remoteAddress), o, odip = ip;
    ip = ip.replace(/::ffff:/gmi,'');
    if(isExists(odip) && odip != ip)
      fs.rename(mypath + odip, mypath + ip,function(e){});
    if(isExists(ip))o = JSON.parse(fs.readFileSync(mypath + ip));
    else
    {
      o = {ip:ip};
      // 内网ip判断
      // o = JSON.parse(child_process.execSync("curl ipinfo.io/" + ip));
    }
    // 更新ua
    if(req.headers && req.headers["user-agent"])
      o["user-agent"] = req.headers["user-agent"];
    if(!o.url)o.url = req.url;
    if(!o.referer && req.headers['referer'])o.referer = req.headers['referer'];
    
    o.date = moment(new Date().getTime()).format('YYYY-MM-DD HH:mm:ss');
    fs.writeFileSync(mypath + ip,JSON.stringify(o));
    return o;
  }catch(e){}
  return {};
}

// 得到ip信息
// https://github.com/d3/d3/wiki/Gallery
function rcip(req,res,next)
{
  res.setHeader("Content-Type", "image/svg+xml");
  var d3n = new D3Node();
  d3n.createSVG(500,500).append('g');
  var s = '<?xml version="1.0" encoding="UTF-8" ?><svg xmlns="http://www.w3.org/2000/svg" version="1.1">'
  s += '<text x="0" y="15" fill="red"><![CDATA[' + JSON.stringify(getIp(req),null,' ') + ']]></text>'
  s += '</svg>';
  res.end(d3n.svgString());
}

app.use('/', rcip);
app.use(function(req, res, next)
{
  getIp(req);
  next();
});
// 异常发生了，还是继续处理
app.use(function(err, req, res, next) 
{
  rcip(req,res,next);
});
module.exports = app;
app.listen(8080);