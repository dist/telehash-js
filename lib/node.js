'use strict';

var logger = require('./logging');
var locals = require('./locals');
var utilities = require('./utilities');
var defaults = require('./defaults');
var transport = require('./transport');

var local = locals.local;

// this creates a hashname identity object (or returns existing)
function whois(hashname)
{
  /*jshint validthis: true */
  var self = this;
  // validations
  if(!hashname){
    logger.warn('whois called without a hashname', hashname);
    return false;
  }
  if(typeof hashname != 'string'){
    logger.warn('wrong type, should be string', typeof hashname,hashname);
    return false;
  }
  hashname = hashname.split(',')[0]; // convenience if an address is passed in
  if(!utilities.isHEX(hashname, 64)){
    logger.warn('whois called without a valid hashname', hashname);
    return false;
  }

  // so we can check === self
  if(hashname === self.hashname) return self;

  var hn = self.all[hashname];
	if(hn) return hn;
  
  // make a new one
  hn = self.all[hashname] = {hashname:hashname, chans:{}, self:self, paths:[], possible:{}, isAlive:0};
  hn.address = hashname;
  hn.at = Date.now();

  // to create a new channels to this hashname
  hn.start = transport.channel;
  hn.raw = transport.raw;

  // different timeout values based on if there's possibly a nat between us
  hn.timeout = function()
  {
    var ip4 = hn.address.split(',')[1];
    // no ipv4 path, no nat
    if(!ip4 || !self.paths.lan4){
      return defaults.idle_timeout;
    }
    // if one is local and the other is not
    if(utilities.isLocalIP(self.paths.lan4.ip) && !utilities.isLocalIP(ip4)){
      return defaults.nat_timeout;
    }else{
      return defaults.idle_timeout;
    }
  };

  // manage network information consistently, called on all validated incoming packets
  hn.pathIn = function(path)
  {
    if(['ipv4','ipv6','http','bridge','relay','webrtc'].indexOf(path.type) == -1){
      logger.warn('unknown path type', JSON.stringify(path));
      return path;
    }

    // relays are special cases, not full paths
    if(path.type == 'relay'){
      if(hn.relay && hn.relay.id == path.id){
        return hn.relay; // already exists
      }
      logger.debug('relay incoming',hn.hashname,JSON.stringify(path));
      hn.relay = path; // set new default relay
      hn.alive = false; // a new relay is a red flag
      // trigger sync whenever a relay is added (slightly delayed so other internal async stuff can happen first)
      // var started = Date.now();
      setTimeout(function(){
        logger.debug('relay only, trying sync',hn.hashname);
        hn.sync(function(){
          // if we found another path, yay
          if(hn.alive){
            return logger.debug('relay upgraded, now alive',hn.hashname);
          }
          // only relay yet, try to create a bridge
          self.bridge(hn, function(pathin, via){
            logger.debug('BRIDGING',hn.hashname,pathin,via&&via.hashname);
            if(!pathin){
              return logger.debug('no bridge');
            }
            hn.bridge = via.hashname;
            // experimentally send direct via the bridge path now
            hn.raw('path',{
              js:{
                priority:0
              },
              direct:pathin
            }, transport.inPath);
          });
        });
      },10);
      return path;
    }
    
    // anything else incoming means hn is alive
    if(!hn.alive){
      logger.debug('aliving',hn.hashname,JSON.stringify(path));
    }
    hn.alive = true;

    var match = utilities.pathMatch(path, hn.paths);
    if(!match){
      // store a new path
      hn.paths.push(path);
      match = path;

      // if bridging, and this path is from the bridge, flag it for lower priority
      if(hn.bridge && utilities.pathMatch(path, self.whois(hn.bridge).paths)){
        path.priority = -1;
      }

      // always default to minimum 0 here
      if(typeof path.priority != 'number'){
        path.priority = 0;
      }

      // when multiple networks detected, trigger a sync
      if(hn.paths.length > 1){
        hn.sync();
      }

      // update public ipv4 address
      if(path.type == 'ipv4' && !utilities.isLocalIP(path.ip)){
        hn.address = [hn.hashname,path.ip,path.port].join(',');
      }
      
      // track overall if we trust them as local
      if(path.type.indexOf('ip') === 0 && utilities.isLocalIP(path.ip)){
        hn.isLocal = true;
      }

      // track overall if they are connected via a public IP network
      if(path.type.indexOf('ip') === 0 && !utilities.isLocalIP(path.ip)){
        hn.isPublic = true;
      }
    }
    
    // track last active timestamp
    match.lastIn = Date.now();

    return match;
  };
  
  // try to send a packet to a hashname, doing whatever is possible/necessary
  hn.send = function(packet){
    // if there's a line, try sending it via a valid network path!
    if(hn.lineIn)
    {
      logger.debug('line sending',hn.hashname,hn.lineIn);
      var lined = packet.msg || local.lineize(hn, packet);
      
      // directed packets are a special case (path testing), dump and forget
      if(packet.direct){
        return self.send(packet.direct, lined, hn);
      }
      
      hn.sentAt = Date.now();

      // validate if a network path is acceptable to stop at
      var validate = function(path)
      {
        if(Date.now() - path.lastIn < 5000){
          return true; // just received something
        }
        if(!path.lastOut){
          return false; // is old and haven't sent anything
        }
        if(path.lastIn > path.lastOut){
          return true; // received any newer than sent, good
        }
        if((path.lastOut - path.lastIn) < 5000){
          return true; // received within 5sec of last sent
        }
        return false; // there are cases where it's still valid, but it's always safer to assume otherwise
      };

      // sort all possible paths by preference, priority and recency
      var paths = hn.paths.sort(function(a,b){
        if(packet.to && a === packet.to){
          return 1; // always put the .to at the top of the list, if any
        }
        if(a.priority == b.priority){
          return a.lastIn - b.lastIn;
        }
        return b.priority - a.priority;
      });
      
      // try them in order until there's a valid one
      for(var i = 0; i < paths.length; i++)
      {
        var path = paths[i];
        // validate first since it uses .lastOut which .send updates
        var valid = validate(path);
        if(!valid){
          logger.debug('possibly dead path',JSON.stringify(path));
        }
        self.send(path, lined, hn);
        if(valid){
          return; // any valid path means we're done!
        }
      }

      // when not alive and there's a relay, we have to try it
      if(!hn.alive && hn.relay)
      {
        if(packet.sender && packet.sender.type == 'relay'){
          return logger.debug('skipping double-relay path',JSON.stringify(packet.sender),JSON.stringify(hn.relay));
        }
        self.send(hn.relay, lined, hn);
        if(hn.relay){
          return; // assume the relay worked if it exists yet
        }
      }

    }

    // we've fallen through, either no line, or no valid paths
    logger.debug('alive failthrough',hn.sendSeek,Object.keys(hn.vias||{}));
    hn.alive = false;
    hn.lastPacket = packet; // will be resent if/when an open is received
    hn.open(); // always try an open again

    // also try using any via informtion to create a new line
    function vias()
    {
      if(!hn.vias){
        return;
      }
      hn.sentOpen = false; // whenever we send a peer, we'll always need to resend any open regardless
      // try to connect vias
      var todo = hn.vias;
      delete hn.vias; // never use more than once
      Object.keys(todo).forEach(function(via){
        var address = todo[via].split(',');
        if(address.length == 3 && address[1].split('.').length == 4 && parseInt(address[2]) > 0){
          // NAT hole punching
          var path = {
            type:'ipv4',
            ip:address[1],
            port:parseInt(address[2])
          };
          self.send(path,local.pencode());
          // if possibly behind the same NAT, set flag to allow/ask to relay a local path
          if(self.nat && address[1] == (self.paths.pub4 && self.paths.pub4.ip)){
            hn.relayAsk = 'local';
          }
        }else{ // no ip address, must relay
          hn.relayAsk = true;
        }
        // TODO, if we've tried+failed a peer already w/o a relay, add relay
        self.whois(via).peer(hn.hashname, hn.relayAsk); // send the peer request
      });
    }
    
    // if there's via information, just try that
    if(hn.vias){
      return vias();
    }
    

    // never too fast, worst case is to try to seek again
    if(!hn.sendSeek || (Date.now() - hn.sendSeek) > 5000)
    {
      hn.sendSeek = Date.now();
      self.seek(hn, function(err){
        if(!hn.lastPacket){
          return; // packet was already sent elsewise
        }
        vias(); // process any new vias
      });
    }

  };

  // handle all incoming line packets
  hn.receive = function(packet)
  {
  //    if((Math.floor(Math.random()*10) == 4)) return warn("testing dropping randomly!");
    if(!packet.js || !utilities.isHEX(packet.js.c, 32)){
      return logger.warn('dropping invalid channel packet');
    }

    logger.debug('LINEIN',JSON.stringify(packet.js));
    hn.recvAt = Date.now();
    // normalize/track sender network path
    packet.sender = hn.pathIn(packet.sender);

    // find any existing channel
    var chan = hn.chans[packet.js.c];
    if(chan){
      return chan.receive(packet);
    }

    // start a channel if one doesn't exist, check either reliable or unreliable types
    var listening = {};
    if(typeof packet.js.seq == 'undefined'){
      listening = self.raws;
    }
    if(packet.js.seq === 0){
      listening = self.rels;
    }
    if(!listening[packet.js.type])
    {
      // bounce error
      if(!packet.js.end && !packet.js.err)
      {
        logger.warn('bouncing unknown channel/type',packet.js);
        var err = (packet.js.type) ? 'unknown type' : 'unknown channel';
        hn.send({
          js:{
            err:err,
            c:packet.js.c
          }
        });
      }
      return;
    }
    // make the correct kind of channel;
    var kind = (listening == self.raws) ? 'raw' : 'start';
    chan = hn[kind](packet.js.type, {id:packet.js.c}, listening[packet.js.type]);
    chan.receive(packet);
  };
  
  // track who told us about this hn
  hn.via = function(from, address)
  {
    if(typeof address != 'string'){
      return logger.warn('invalid see address',address);
    }
    if(!hn.vias){
      hn.vias = {};
    }
    if(hn.vias[from.hashname]){
      return;
    }
    hn.vias[from.hashname] = address; // TODO handle multiple addresses per hn (ipv4+ipv6)
  };
  
  // just make a seek request conveniently
  hn.seek = function(hashname, callback)
  {
    var tries = 0;
    function seek()
    {
      tries++;
      if(tries == 4){
        callback('timed out', []);
      }
      if(tries > 3){
        return;
      }
      setTimeout(seek, 1000);
      hn.raw('seek', {
        js:{
          'seek':hashname
        }
      }, function(err, packet, chan){
        if(tries > 3){
          return; // already failed back
        }
        tries = 5; // prevent multiple callbacks
        callback(packet.js.err,Array.isArray(packet.js.see)?packet.js.see:[]);
      });
    }
    seek();
  };
  
  // send a simple lossy peer request, don't care about answer
  hn.peer = function(hashname, relay)
  {
    var js = {
      type:'peer',
      end:true,
      'peer':hashname,
      c:local.randomHEX(16)
    };
    js.paths = [];
    if(self.paths.pub4){
      js.paths.push({
        type:'ipv4',
        ip:self.paths.pub4.ip,
        port:self.paths.pub4.port
      });
    }
    if(self.paths.pub6){
      js.paths.push({
        type:'ipv6',
        ip:self.paths.pub6.ip,
        port:self.paths.pub6.port
      });
    }
    if(self.paths.http){
      js.paths.push({
        type:'http',
        http:self.paths.http.http
      });
    }
    // note: don't include webrtc since it's private and done during a path sync
    if(hn.isLocal)
    {
      if(self.paths.lan4){
        js.paths.push({
          type:'ipv4',
          ip:self.paths.lan4.ip,
          port:self.paths.lan4.port
        });
      }
      if(self.paths.lan6){
        js.paths.push({
          type:'ipv6',
          ip:self.paths.lan6.ip,
          port:self.paths.lan6.port
        });
      }
    }
    if(relay || js.paths.length === 0){
      js.paths.push({
        type:'relay',
        id:local.randomHEX(16)
      });
    }
    hn.send({js:js});
  };

  // force send an open packet, direct overrides the network
  hn.open = function(direct)
  {
    if(!hn.der){
      return; // can't open if no key
    }
    if(!direct && hn.paths.length === 0){
      return logger.debug('can\'t open, no path');
    }
    // don't send again if we've sent one in the last few sec, prevents connect abuse
    if(hn.sentOpen && (Date.now() - hn.sentOpen) < 2000){
      return;
    }
    hn.sentOpen = Date.now();

    // generate just one open packet, so recipient can dedup easily if they get multiple
    var open = local.openize(self, hn);

    // send directly if instructed
    if(direct){
      if(direct.type == 'relay')
      {
        var relay = self.whois(direct.via);
        relay.raw('relay', {
          id:direct.id,
          js:{
            'to':hn.hashname
          },
          body:open
        }, transport.inRelayMe);
      }else{
        self.send(direct, open, hn);
      }
    }else{
      // always send to all known paths, increase resiliency
      hn.paths.forEach(function(path){
        self.send(path, open, hn);
      });
      if(hn.relay){
        self.send(hn.relay, open, hn);
      }
    }

  };
  
  // send a full network path sync, callback(true||false) if err (no networks)
  hn.sync = function(callback)
  {
    if(!callback){
      callback = function(){};
    }
    logger.debug('syncing',hn.hashname,JSON.stringify(hn.paths));
    
    // check which types of paths we have to them
    var types = {};
    hn.paths.forEach(function(path){
      types[path.type] = true;
    });

    // clone the paths and add in relay if one
    var paths = hn.paths.slice();
    if(!hn.alive && hn.relay){
      paths.push(hn.relay);
    }

    // empty. TODO should we do something?
    if(paths.length === 0){
      return callback();
    }

    // check all paths at once
    var refcnt = paths.length;
    paths.forEach(function(path){
      logger.debug('PATHLOOP',paths.length,JSON.stringify(path));
      var js = {};
      // our outgoing priority of this path
      if(path.type == 'relay'){
        js.priority = 0;
      }else{
        js.priority = 1;
      }
      var alts = [];
      // if no ip paths and we have some, signal them
      if(!types.ipv4 && self.paths.pub4){
        alts.push({
          type:'ipv4',
          ip:self.paths.pub4.ip,
          port:self.paths.pub4.port
        });
      }
      if(!types.ipv6 && self.paths.pub6){
        alts.push({
          type:'ipv6',
          ip:self.paths.pub6.ip,
          port:self.paths.pub6.port
        });
      }
      // if we support http path too
      if(!types.http && self.paths.http){
        alts.push({
          type:'http',
          http:self.paths.http.http
        });
      }
      // if we support webrtc
      if(!types.webrtc && self.paths.webrtc){
        alts.push({
          type:'webrtc',
          id:local.randomHEX(16)
        });
      }
      // include local ip/port if we're relaying to them
      if(hn.relayAsk == 'local')
      {
        if(self.paths.lan4){
          alts.push({
            type:'ipv4',
            ip:self.paths.lan4.ip,
            port:self.paths.lan4.port
          });
        }
        if(self.paths.lan6){
          alts.push({
            type:'ipv6',
            ip:self.paths.lan6.ip,
            port:self.paths.lan6.port
          });
        }
      }
      if(alts.length > 0){
        js.paths = alts;
      }
      hn.raw('path',{
        js:js,
        timeout:3000,
        direct:path
      }, function(err, packet){
        // when it actually errored, lower priority
        if(err && err !== true){
          path.priority = -10;
        }
        else{
          transport.inPath(true, packet); // handles any response .priority and .paths
        }
        // processed all paths, done
        if((--refcnt) === 0){
          callback();
        }
      });
    });
  };

  // create an outgoing TeleSocket
  hn.socket = function(pathname)
  {
    if(!pathname){
      pathname = '/';
    }
    // passing id forces internal/unescaped mode
    var chan = hn.start('ts',{
      id:local.randomHEX(16),
      js:{
        path:pathname
      }
    });
    chan.wrap('TS');
    return chan.socket;
  };
  
  return hn;
}

function online(callback)
{
  /*jshint validthis: true */
  var self = this;
  // ping lan
  self.lanToken = local.randomHEX(16);
  self.send({
    type:'lan'
  }, local.pencode({
    type:'lan',
    lan:self.lanToken
  }));
  // start mesh maint
  transport.meshLoop(self);
  // safely callback only once or when all seeds failed
  function done(err)
  {
    if(!dones){
      return; // already called back
    }
    // success!
    if(!err)
    {
      callback();
      dones = 0;
      return;
    }
    dones--;
    // failed
    if(!dones){
      callback(err);
    }
  }
  var dones = self.seeds.length;
  if(!dones) {
    logger.warn('no seeds');
    dones++;
    return done();
  }
  self.seeds.forEach(function(seed){
    seed.seek(self.hashname, function(err, see){
      if(Array.isArray(see)){
          see.forEach(function(item){
            self.via(seed, item); // myVia()
          });
        }
      done(err);
    });
  });
}


exports.whois = whois;
exports.online = online;