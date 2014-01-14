'use strict';

var utilities = require('./utilities');
var logger = require('./logging');
var locals = require('./locals');
var transport = require('./transport');
var mesh = require('./mesh');
var defaults = require('./defaults');
var seed = require('./seed');
var node = require('./node');
var dht = require('./dht');
var channel = require('./channel');



// hackjib
exports.debug = logger.setDebug;
exports.defaults = defaults;

// hackjib
// dependency functions
var local = locals.local;
exports.genkey = local.genkey;
exports.localize = locals.localize;

exports.isHashname = function(hex)
{
  return utilities.isHEX(hex, 64);
};

exports.channelWraps =channel.channelWraps;

exports.isLocalIP = utilities.isLocalIP;

// start a hashname listening and ready to go
exports.hashname = function(key, send, args)
{
  if(!local){
    return logger.warn('thjs.localize() needs to be called first');
  }
  if(!key || !key.public || !key.private){
    return logger.warn('bad args to hashname, requires key.public and key.private');
  }
  if(!local.pub2key(key.public) || !local.pri2key(key.private)){
    return logger.warn('key.public and key.private must be valid pem strings');
  }
  if(typeof send !== 'function'){
    return logger.warn('second arg needs to be a function to send packets, is', typeof send);
  }

  // configure defaults
  if(!args){
    args = {};
  }

  var self = {
    seeds:[],
    locals:[],
    lines:{},
    bridges:{},
    all:{},
    buckets:[],
    capacity:[],
    rels:{},
    raws:{},
    paths:{},
    bridgeIVs:{},
    TSockets:{}
  };

  self.private = local.pri2key(key.private);
  self.public = local.pub2key(key.public);
  self.der = local.key2der(self.public);
  self.address = self.hashname = local.der2hn(self.der);
  self.nat = false;

  // udp socket stuff
  self.pcounter = 1;
  self.receive = transport.receive;

  // outgoing packets to the network
	self.send = function(path, msg, to){
    if(!path){
      return logger.warn('send called w/ no network, dropping');
    }
    path.lastOut = Date.now();
    // a relay network must be resolved to the channel and wrapped/sent that way
    if(path.type == 'relay')
    {
      var via = self.whois(path.via);
      if(!via || !via.chans[path.id] || !via.alive)
      {
        logger.debug('dropping dead relay via',JSON.stringify(path),via&&via.alive);
        if(to){
          to.relay = false;
        }
        return;
      }
      // must include the sender path here to detect double-relay
      return via.chans[path.id].send({
        sender:path,
        js:{
          type:'relay',
          to:to.hashname
        },
        body:msg
      });
    }
    // hand rest to the external sending function passed in
    if(typeof msg.length == 'function'){
      logger.debug('out',msg.length());
    }else{
      logger.debug('out',msg.length,JSON.stringify(path),to&&to.hashname);
    }
	  send(path, msg, to);
	};
  self.pathSet = function(path){
    var updated = (self.paths[path.type] && JSON.stringify(self.paths[path.type]) == JSON.stringify(path));
    self.paths[path.type] = path;
    // if ip4 and local ip, set nat mode
    if(path.type == 'ipv4'){
      self.nat = utilities.isLocalIP(path.ip);
    }
    // trigger pings if our address changed
    if(updated){
      mesh.meshPing(self);
    }
  };
  
  // need some seeds to connect to, addSeed({ip:"1.2.3.4", port:5678, public:"PEM"})
  self.addSeed = seed.addSeed;
	
	// map a hashname to an object, whois(hashname)
	self.whois = node.whois;
  
  // connect to the network, online(callback(err))
  self.online = node.online;
  
  // handle new reliable channels coming in from anyone
  self.listen = function(type, callback){
    if(typeof type != 'string' || typeof callback != 'function'){
      return logger.warn('invalid arguments to listen');
    }
    if(type.substr(0,1) !== '_'){
      type = '_'+type;
    }
    self.rels[type] = callback;
  };
  // advanced usage only
  self.raw = function(type, callback){
    if(typeof type != 'string' || typeof callback != 'function'){
      return logger.warn('invalid arguments to raw');
    }
    self.raws[type] = callback;
  };

  // TeleSocket handling
  //   - to listen pass path-only uri "/foo/bar", fires callback(socket) on any incoming matching uri
  //   - to connect, pass in full uri "ts://hashname/path" returns socket
  self.socket = function(uri, callback)
  {
    if(typeof uri != 'string'){
      return logger.warn('invalid TS uri')&&false;
    }
    // detect connecting socket
    if(uri.indexOf('ts://') === 0){
      var parts = uri.substr(5).split('/');
      var to = self.whois(parts.shift());
      if(!to){
        return logger.warn('invalid TS hashname')&&false;
      }
      return to.socket(parts.join('/'));
    }
    if(uri.indexOf('/') !== 0){
      return logger.warn('invalid TS listening uri')&&false;
    }
    logger.debug('adding TS listener',uri);
    self.TSockets[uri] = callback;
  };
	self.rels.ts = transport.inTS;
  
	// internal listening unreliable channels
	self.raws.peer = transport.inPeer;
	self.raws.connect = transport.inConnect;
	self.raws.seek = transport.inSeek;
	self.raws.relay = transport.inRelay;
	self.raws.path = transport.inPath;
	self.raws.bridge = transport.inBridge;

  // primarily internal, to seek/connect to a hashname
  self.seek = dht.seek;
  self.via = dht.myVia;
  self.bridge = dht.bridge;
  
  // return array of closest known hashname objects
  self.nearby = dht.nearby;

  return self;
};