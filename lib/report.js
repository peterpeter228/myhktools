module.exports={
	tags:"report",// 报告处理插件
	doCheck:function(o,_t)
	{
		g_oRstAll[o.url]=o;
		
		if(o && o.vul)
		{
			// console.log(_t.tags);
			console.log(o);
			// console.log(_t);
		}
		if(program.cmd)console.log(o.body);
	}
};