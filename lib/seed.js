'use strict';

var locals = require('./locals');
var logger = require('./logging');
var utilities = require('./utilities');

var local = locals.local;

function addSeed(arg) {
  /*jshint validthis: true */
  var self = this;
  if(!arg.pubkey){
    return logger.warn('invalid args to addSeed');
  }
  var der = local.key2der(arg.pubkey);
  var seed = self.whois(local.der2hn(der));
  if(!seed){
    return logger.warn('invalid seed info',arg);
  }
  if(seed === self){
    return; // can't add ourselves as a seed
  }
  seed.der = der;
  var path;
  if(arg.ip)
  {
    path = {
      type:'ipv4',
      ip:arg.ip,
      port:arg.port,
      priority:-2
    };
    if(!utilities.pathMatch(path, seed.paths)){
      seed.paths.push(path);
    }
    seed.address = [seed.hashname,arg.ip,arg.port].join(','); // given ip:port should always be the most valid
  }
  if(arg.ip6)
  {
    path = {
      type:'ipv6',
      ip:arg.ip6,
      port:arg.port6,
      priority:-1
    };
    if(!utilities.pathMatch(path, seed.paths)){
      seed.paths.push(path);
    }
  }
  if(arg.http)
  {
    path = {
      type:'http',
      http:arg.http,
      priority:-2
    };
    if(!utilities.pathMatch(path, seed.paths)){
      seed.paths.push(path);
    }
  }
  if(arg.bridge){
    seed.bridging = true;
  }
  seed.isSeed = true;
  self.seeds.push(seed);
}

exports.addSeed = addSeed;