var QrCode = require('qrcode-reader'),
	fs  = require("fs"),
	qc = require('qrcode');

/*
L (Low)	~7%
M (Medium)	~15%
Q (Quartile)	~25%
H (High)	~30%
version:2,
*/
function encodeQrCode(data,cbk)
{
	qc.toDataURL(data,{errorCorrectionLevel:"H"}, function (e, url) 
	{
  		if(e)console.log(e);else cbk(url);
	});
}	

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

module.exports = {"deCodeQrCode":deCodeQrCode,"encodeQrCode":encodeQrCode};

//*
if(process.argv)
{
	var a = process.argv.splice(2);
	if(a && 0 < a.length)
	{
		var buffer = fs.readFileSync(a[0]);
		deCodeQrCode(buffer.toDataURL(),
			function(s)
			{
				console.log(s);
			});
	}
}//*/