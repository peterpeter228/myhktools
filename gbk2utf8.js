var a = process.argv.splice(2),
	fs = require('fs'),
    k = fs.readFileSync(a[0]),
    iconv = require("iconv-lite");
k = iconv.decode(k,"gbk").toString("utf8");

fs.writeFileSync(a[0],k);
console.log(k);