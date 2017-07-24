/*
npm install gps-util exif -g
*/
var a = process.argv.splice(2),
  fs = require("fs"),
  request = require("request"),
	gpsUtil = require("gps-util"),
  exif = require("exif").ExifImage;

function fmt(d)
{
   return require('moment')(d).format('YYYY-MM-DD HH:mm:ss');
}
var aGpsO = {};
// 获取图片的经纬度信息
new exif({image:a[0]},function(e,d)
{
  fs.stat(a[0],function(e,stats)
  {
    // GPSLatitudeRef：S 南方；N北方 GPSLongitudeRef：W 西方 E 东方
    aGpsO.fileName = a[0];
    if(stats && stats.birthtime)aGpsO.createTime = fmt(stats.birthtime);
    
    if(d && d.gps && d.gps.GPSLatitude && d.gps.GPSLongitude)
    {
      // console.log(d.gps);
      var aK = d.gps.GPSLatitude, aK2 = d.gps.GPSLongitude,
          aGps = [aK[0] + aK[1] / 60 + aK[2] / 3600, aK2[0] + aK2[1] / 60 + aK2[2] / 3600]
      if('S' == d.gps.GPSLatitudeRef)aGps[0] = 0 - aGps[0];
      if('W' == d.gps.GPSLongitudeRef)aGps[1] = 0 - aGps[1];
      aGpsO.GPSLatitude = aGps[0];
      aGpsO.GPSLongitude = aGps[1];
    }
    request.get("http://maps.googleapis.com/maps/api/geocode/json?latlng="
     + aGpsO.GPSLatitude + ","
     + aGpsO.GPSLongitude + "&sensor=false",function(e,r)
    {
      if(!e)
      {
        var oR = JSON.parse(r.body);
        if("OK" == oR.status)
        {
           if(oR.results && oR.results.length)
           {
              aGpsO.address = oR.results[0].formatted_address;
           }
        }// console.log(r.body);
      }
    });
    
  });
	/*
	var k = gpsUtil.getTotalDistance([{lat:57.90360046457607, 
		lng:3.0384}],function(e,d)
		{

			console.log(arguments.length);
		});
	*/
});

process.on('exit', (code) => 
{
  console.log(JSON.stringify(aGpsO,null,' '));
});
/*
{ image: 
   { XResolution: 72,
     YResolution: 72,
     ResolutionUnit: 2,
     Software: 'Adobe Photoshop CS5 Windows',
     YCbCrPositioning: 1,
     ExifOffset: 142,
     GPSInfo: 232 },
  thumbnail: 
   { Compression: 0,
     XResolution: 72,
     YResolution: 72,
     ResolutionUnit: 0,
     ThumbnailOffset: 440,
     ThumbnailLength: 7984 },
  exif: 
   { ExifVersion: <Buffer 30 32 32 31>,
     ComponentsConfiguration: <Buffer 01 02 03 00>,
     FlashpixVersion: <Buffer 30 31 30 30>,
     ColorSpace: 1,
     ExifImageWidth: 800,
     ExifImageHeight: 600,
     SceneCaptureType: 0 },
  gps: 
   { GPSVersionID: [ 2, 3, 0, 0 ],
     GPSLatitudeRef: 'N',
     GPSLatitude: [ 64, 1, 57.90360046457607 ],
     GPSLongitudeRef: 'W',
     GPSLongitude: [ 22, 39, 3.0384 ] },
  interoperability: {},
  makernote: {} }
*/
