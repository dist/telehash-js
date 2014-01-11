'use strict';

var warn = function(){
  console.log.apply(console,arguments);
  return undefined;
};

var debug = function(){
};

var setDebug = function(cb){
  //debug = cb;
};

var setWarn = function(cb){
  warn = cb;
};

exports.warn = warn;
exports.debug = debug;
exports.setDebug = setDebug;
exports.setWarn = setWarn;