/*
npm install gps-util exif -g
*/
var a = process.argv.splice(2),
	gpsUtil = require("gps-util"),
    exif = require("exif").ExifImage;
new exif({image:a[0]},function(e,d)
{
	console.log(d.gps);
	/*
	var k = gpsUtil.getTotalDistance([{lat:57.90360046457607, 
		lng:3.0384}],function(e,d)
		{

			console.log(arguments.length);
		});
	*/
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
