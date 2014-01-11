'use strict';

// just return true/false if it's at least the format of a sha1
function isHEX(str, len)
{
  if(typeof str !== 'string'){
    return false;
  }
  if(str.length !== len){
    return false;
  }
  if(str.replace(/[a-f0-9]+/i, '').length !== 0){
    return false;
  }
  return true;
}

// XOR distance between two hex strings, high is furthest bit, 0 is closest bit, -1 is error
function dhash(h1, h2) {
  // convert to nibbles, easier to understand
  var n1 = hex2nib(h1);
  var n2 = hex2nib(h2);
  if(!n1.length || n1.length != n2.length){
    return -1;
  }
  // compare nibbles
  var sbtab = [-1,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3];
  var ret = 252;
  for (var i = 0; i < n1.length; i++) {
      var diff = n1[i] ^ n2[i];
      if (diff){
        return ret + sbtab[diff];
      }
      ret -= 4;
  }
  return -1; // samehash
}

// convert hex string to nibble array
function hex2nib(hex)
{
  var ret = [];
  for (var i = 0; i < hex.length / 2; i ++) {
      var bite = parseInt(hex.substr(i * 2, 2), 16);
      if (isNaN(bite)){
        return [];
      }
      ret[ret.length] = bite >> 4;
      ret[ret.length] = bite & 0xf;
  }
  return ret;
}

function pathMatch(path1, paths)
{
  var match;
  paths.forEach(function(path2){
    switch(path1.type)
    {
    case 'ipv4':
    case 'ipv6':
      if(path1.ip == path2.ip && path1.port == path2.port){
        match = path2;
      }
      break;
    case 'http':
      if(path1.http == path2.http){
        match = path2;
      }
      break;
    case 'bridge':
    case 'relay':
    case 'webrtc':
      if(path1.id == path2.id){
        match = path2;
      }
      break;
    }
  });
  return match;
}

// return if an IP is local or public
function isLocalIP(ip)
{
  // ipv6 ones
  if(ip.indexOf(':') >= 0)
  {
    if(ip.indexOf('::') === 0){
      return true; // localhost
    }
    if(ip.indexOf('fc00') === 0){
      return true;
    }
    if(ip.indexOf('fe80') === 0){
      return true;
    }
    return false;
  }
  
  var parts = ip.split('.');
  if(parts[0] == '0'){
    return true;
  }
  if(parts[0] == '127'){
    return true; // localhost
  }
  if(parts[0] == '10'){
    return true;
  }
  if(parts[0] == '192' && parts[1] == '168'){
    return true;
  }
  if(parts[0] == '172' && parts[1] >= 16 && parts[1] <= 31){
    return true;
  }
  if(parts[0] == '169' && parts[1] == '254'){
    return true; // link local
  }
  return false;
}

exports.isHEX = isHEX;
exports.dhash = dhash;
exports.isLocalIP = isLocalIP;
exports.pathMatch = pathMatch;