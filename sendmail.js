// proxychains4 -f ~/pc.conf  node sendmail.js 
const sendmail = require('sendmail')();
function fnMySendMail(s,t,b)
{
	sendmail({
	    // from: 'love2000@sougou.com',
	    from: 'xiaozhang@sougou.com',
	    // from: s,
	    to: s,
	    subject: t,
	    // 邮件跟踪功能，当对方阅读后，能够从http://23.105.209.65/获取到阅读邮件的ip、user-agent等信息
	    html: b+'<img src=http://23.105.209.65/' + s + '>'
	    /*
	    ,attachments:[
	    {
	    	filename: '图',
      		content: require('fs').readFileSync('file.png')
	    }]
	    //////*/
	  }, function(err, reply) {
	    console.log(err && err.stack);
	    console.dir(reply);
	});
}

fnMySendMail("Your@qq.com",'标题','内容....愿你安好');
