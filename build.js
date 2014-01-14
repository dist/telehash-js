'use strict';

var browserify = require('browserify');
var fs = require('fs');
var UglifyJS = require('uglify-js');
var bundle1 = fs.createWriteStream('./build/bundle1.js');
var bundle = './build/bundle.js';


var includes = [
	'lib/crypto/includes/browser/forge.min.js',
	'lib/crypto/includes/browser/jsbn.js',
	'lib/crypto/includes/browser/jsbn2.js',
	'lib/crypto/includes/browser/ec.js',
	'lib/crypto/includes/browser/sec.js',
	'lib/crypto/includes/browser/prng4.js',
	'lib/crypto/includes/browser/rng.js',
	'build/bundle1.js',
	'lib/webrtc.js',
	'seeds.js'
];


var b = browserify();
b.add('./thjs.js');

b.bundle().pipe(bundle1);



bundle1.on('finish', function () {
	fs.truncateSync(bundle, 0);
	fs.truncateSync('./examples/browser/js/bundle.js', 0);
	var data = UglifyJS.minify(includes);
	// temp hack
	data.code = data.code.replace('"use strict";','');
	fs.appendFileSync(bundle, data.code);
	fs.appendFileSync('./examples/browser/js/bundle.js', data.code);
	fs.unlink('./build/bundle1.js');
});



