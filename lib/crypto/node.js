'use strict';

var crypt = require('./crypt');

// use either the crypt (compiled, faster) libs or the forge-based pure js ones
if(!crypt.validate()){
	crypt = require('./cryptjs').load();
}

module.exports = crypt;