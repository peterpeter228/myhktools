module.exports={
	tags:"report",// 报告处理插件
	doCheck:function(o,_t)
	{
		if(o && o.vul)
		{
			// console.log(_t.tags);
			delete o.send;
			delete o.body;
			console.log(o);
			// console.log([_t.tags,o.url]);
			// console.log(_t);
		}
		if(program.cmd)console.log(o.body);
	}
};