// 别忘记了，后渗透meterpreter会产生大量的gbk文件，在mac osx、linux下无法正常阅读
var a = process.argv.splice(2),
	fs = require('fs'),
    iconv = require("iconv-lite");

function doFile(filename)
{
	fs.stat(filename,function(e,stats)
	{
		if(stats.isFile() && /\.(txt|log)/gmi.test(filename) && fs.existsSync(filename))
		{
			try{
				var k = fs.readFileSync(filename);
				k = iconv.decode(k,"gbk").toString("utf8");
				fs.writeFileSync(filename,k);
				console.log(filename);
				console.log(k);
			}catch(e1){console.log(e1);}
		}
		else if(stats.isDirectory())
		{
			fs.readdir(filename,{},function(e,aF)
			{
				aF.forEach(function(i)
				{
					if(".DS_Store" == i)
					{
						fs.unlinkSync(filename + "/" + i);
					}
					else doFile(filename + "/" + i);
				});
			});
		}
	});
}

doFile(a[0]);

