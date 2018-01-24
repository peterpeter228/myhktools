module.exports={
	tags:"report",// 报告处理插件
	doCheck:function(o,_t)
	{
		if(o && o.vul)console.log(o);
		// console.log(_t);
	}
};