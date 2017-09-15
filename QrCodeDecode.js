var QrCode = require('qrcode-reader');

function deCodeQrCode(data,cbk)
{
	var qr = new QrCode();
	qr.callback = function(error, result) 
	{
	  if(error) {
	    console.log(error)
	    return;
	  }
	  cbk(result);
	};
	qr.decode(data);
}

module.exports = {"deCodeQrCode":deCodeQrCode};

//*
if(process.argv)
{
	var a = process.argv.splice(2);
	if(a && 0 < a.length)
	deCodeQrCode(a[0],
		function(s)
	{
		console.log(s);
	});
}//*/