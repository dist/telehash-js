'use strict';

var logger = require('./logging');
var utilities = require('./utilities');
var locals = require('./locals');
var bucket = require('./bucket');

// hackjib
// dependency functions
var local = locals.local;

// self.receive, raw incoming udp data
function receive(msg, path)
{
  /*jshint validthis: true */
	var self = this;

  // decode message
  var packet = local.pdecode(msg);
  if(!packet){
    logger.warn('failed to decode a packet from', path, msg.toString());
    return;
  }

  // empty packets are NAT pings
  if(Object.keys(packet.js).length === 0){
    return;
  }
  
  packet.sender = path;
  packet.id = self.pcounter++;
  packet.at = Date.now();

  if(typeof msg.length == 'function'){
    logger.debug('in',msg.length());
  }else{
    logger.debug('in',msg.length, packet.js.type, packet.body && packet.body.length,JSON.stringify(path));
  }

  // process the packet
  var resp;

  switch(packet.js.type){
    case 'lan'  :
          resp = inLan(self, packet);
          break;
    case 'seed' :
          resp = inLanSeed(self, packet);
          break;
    case 'open' :
          resp = openPath(self,packet,path);
          break;
    case 'line' :
          resp = openLine(self,packet,path,msg);
          break;
    default :
          logger.warn('dropping incoming packet of unknown type', packet.js, packet.sender);
          break;
  }

  return resp;
}

// type line, open line 
function openLine(self,packet,path,msg){

  if(typeof packet.js.iv != 'string' || packet.js.iv.length != 32){
    logger.warn('missing initialization vector (iv)', path);
    return;
  }

  var line = {};

  line = packet.from = self.lines[packet.js.line];

  // a matching line is required to decode the packet
  if(!line) {
    if(!self.bridges[packet.js.line]){
      logger.debug('unknown line received', packet.js.line, JSON.stringify(packet.sender));
      return;
    }
    logger.debug('BRIDGE',JSON.stringify(self.bridges[packet.js.line]),packet.js.line);

    // drop duplicates
    if(self.bridgeIVs[packet.js.iv]){
      return;
    }
    self.bridgeIVs[packet.js.iv] = true;

    // flat out raw retransmit any bridge packets
    return self.send(self.bridges[packet.js.line],msg);
  }

  // decrypt packet
  local.delineize(packet);

  if(!packet.lineok){
    logger.debug('couldn\'t decrypt line',packet.sender);
    return;
  }

  // process decrypted packet
  line.receive(packet);
}

// type open, open via tha path
function openPath(self,packet,path){

  if(typeof packet.js.iv != 'string' || packet.js.iv.length != 32){
    logger.warn('missing initialization vector (iv)', path);
    return;
  }

  var open = local.deopenize(self, packet);

  if (!open || !open.verify){
    logger.warn('couldn\'t decode open',open);
    return;
  }

  if (!utilities.isHEX(open.js.line, 32)){
    logger.warn('invalid line id enclosed',open.js.line);
    return;
  }
  if(open.js.to !== self.hashname){
    logger.warn('open for wrong hashname',open.js.to);
    return;
  }

  var from = self.whois(local.der2hn(open.rsa));
  if (!from){
    logger.warn('invalid hashname', local.der2hn(open.rsa), open.rsa);
    return;
  }

  // make sure this open is newer (if any others)
  if (typeof open.js.at != 'number'){
    logger.warn('invalid at', open.js.at);
    return;
  }

  // open is legit!
  logger.debug('inOpen verified', from.hashname);
  from.recvAt = Date.now();

  // add this path in
  path = from.pathIn(path);

  // don't re-process a duplicate open
  if (from.openAt && open.js.at <= from.openAt){
    return;
  }

  // update values
  from.openAt = open.js.at;
  from.der = open.rsa;
  from.lineIn = open.js.line;

  // this will send an open if needed
  from.open(path);

  // line is open now!
  local.openline(from, open);
  logger.debug('line open',from.hashname,from.lineOut,from.lineIn);
  self.lines[from.lineOut] = from;

  // add to their bucket
  bucket.bucketize(self, from);
  
  // resend the last sent packet again
  if (from.lastPacket) {
    packet = from.lastPacket;
    delete from.lastPacket;
    from.send(packet);
  }
  
  // if it was a lan seed, add them
  if(from.local && self.locals.indexOf(from) == -1){
    self.locals.push(from);
  }
}

// type lan, looking for a local seed
function inLan(self, packet)
{
  // ignore ourselves
  if(packet.js.lan == self.lanToken){
    return;
  }

  // someone locally is announcing already
  if(self.locals.length > 0){
    return;
  }

  // often immediate duplicates, skip them
  if(self.lanSkip == self.lanToken){
    return;
  }

  self.lanSkip = self.lanToken;

  // announce ourself as the seed back
  packet.js.type = 'seed';
  self.send({
    type:'lan'
  }, local.pencode(packet.js, self.der));

}

// answers from any LAN broadcast notice we sent
function inLanSeed(self, packet)
{
  if(packet.js.lan != self.lanToken){
    return;
  }

  if(self.locals.length >= 5){
    return logger.warn('locals full');
  }

  if(!packet.body || packet.body.length === 0){
    return;
  }

  var der = local.der2der(packet.body);
  var to = self.whois(local.der2hn(der));

  if(!to){
    return logger.warn('invalid lan request from',packet.sender);
  }

  if(to === self){
    return;
  }

  to.der = der;
  to.local = true;

  logger.debug('local seed open',to.hashname,JSON.stringify(packet.sender));
  to.open(packet.sender);
}

// return a see to anyone closer
function inSeek(err, packet, chan)
{
  if(err){
    return;
  }

  if(!utilities.isHEX(packet.js.seek, 64)){
    logger.warn('invalid seek of ', packet.js.seek, 'from:', packet.from.address);
    return;
  }

  // now see if we have anyone to recommend
  var answer = {
    end:true,
    see:packet.from.self.nearby(packet.js.seek).filter(function(hn){
      return hn.address;
    }).map(function(hn){
      return hn.address;
    }).slice(0,5)
  };
  chan.send({
    js:answer
  });
}

// update/respond to network state
function inPath(err, packet, chan)
{
  // check/try any alternate paths
  if(Array.isArray(packet.js.paths)){
    packet.js.paths.forEach(function(path){

      // invalid
      if(typeof path.type != 'string'){
        return;
      }

      // don't send to ones we know about
      if(utilities.pathMatch(path, packet.from.paths)){
        return;
      }

      // a new one, experimentally send it a path
      packet.from.raw('path',{
        js:{
          priority:1
        },
        direct:path
      }, inPath);

      // stash any path for possible bridge
      packet.from.possible[path.type] = path;
    });
  }

  // update any optional priority information
  if(typeof packet.js.priority == 'number'){
    packet.sender.priority = packet.js.priority;
  }

  // bye bye bye!
  if(err){
    return;
  }
  
  // need to respond, prioritize everything above relay
  var priority = (packet.sender.type == 'relay') ? 0 : 2;

  // if bridging, and this path is from the bridge, flag it for lower priority
  if(packet.from.bridge && utilities.pathMatch(packet.sender, packet.from.self.whois(packet.from.bridge).paths)){
    priority = 1;
  }

  chan.send({js:{end:true, priority:priority}});
}

// handle any bridge requests, if allowed
function inBridge(err, packet, chan)
{
  if(err){
    return;
  }

  var self = packet.from.self;

  // ensure valid request
  if(!utilities.isHEX(packet.js.to,32) || !utilities.isHEX(packet.js.from,32) || typeof packet.js.path != 'object'){
    logger.warn('invalid bridge request',JSON.stringify(packet.js),packet.from.hashname);
    return;
  }

  // must be allowed either globally or per hashname
  if(!self.bridging && !packet.from.bridging){
    return chan.send({
      js:{
        err:'not allowed'
      }
    });
  }
  
  // special bridge path for local ips must be "resolved" to a real path
  if(packet.js.path.type == 'bridge' && packet.js.path.local === true){
    var local;
    var to = self.whois(packet.js.path.id);
    // just take the highest priority path
    if(to){
      to.paths.forEach(function(path){
        if(!local){
          local = path;
        }
        if(path.priority > local.priority){
          local = path;
        }
      });
    }
    if(!local){
      return chan.send({
        js:{
          err:'invalid path'
        }
      });
    }
    packet.js.path = local;
  }

  if(!packet.from.bridges){
    packet.from.bridges = {};
  }

  packet.from.bridges[packet.js.to] = packet.from.bridges[packet.js.from] = true; // so we can clean up entries at some point

  // set up the actual bridge paths
  logger.debug('BRIDGEUP',JSON.stringify(packet.js));
  self.bridges[packet.js.to] = packet.js.path;
  self.bridges[packet.js.from] = packet.sender;
  self.bridges[packet.js.to].via = self.bridges[packet.js.from].via = packet.from.hashname;

  chan.send({
    js:{
      end:true
    }
  });
}

// handle any bridge requests, if allowed
function inTS(err, packet, chan, callback)
{
  if(err){
    return;
  }

  var self = packet.from.self;
  callback();

  console.log('INTS',packet.js);

  // ensure valid request
  if(typeof packet.js.path != 'string' || !self.TSockets[packet.js.path]){
    return chan.err('unknown path');
  }
  
  // create the socket and hand back to app
  chan.wrap('TS');
  self.TSockets[packet.js.path](chan.socket);
  chan.send({
    js:{
      open:true
    }
  });
}

// packets coming in to me
function inRelayMe(err, packet, chan)
{
  // TODO clean up anything?
  if(err){
    return;
  }

  if(!packet.body){
    logger.warn('relay in w/ no body',packet.js,packet.from.address);
    return;
  }

  var self = packet.from.self;

  // create a network path that maps back to this channel
  var path = {
    type:'relay',
    id:chan.id,
    via:packet.from.hashname
  };

  self.receive(packet.body, path);
}

// proxy packets for two hosts
function inRelay(err, packet, chan){
  if(err){
    return;
  }

  var self = packet.from.self;

  // new relay channel, validate destination
  if(!utilities.isHEX(packet.js.to, 64)){
    logger.warn('invalid relay of', packet.js.to, 'from', packet.from.address);
    return;
  }

  // if it's to us, handle that directly
  if(packet.js.to == self.hashname){
    return inRelayMe(err, packet, chan);
  }

  // don't relay when it's coming from a relay
  if(packet.sender.type == 'relay'){
    logger.debug('ignoring relay request from a relay',packet.js.to,JSON.stringify(packet.sender));
    return;
  }

  // if to someone else
  var to = self.whois(packet.js.to);

  if(to === packet.from){
    logger.warn('can\'t relay to yourself',packet.from.hashname);
    return;
  }

  if(!to || !to.alive){
    logger.warn('relay to dead hashname', packet.js.to, packet.from.address);
    return;
  }

  // throttle
  if(!packet.from.relayed || Date.now() - packet.from.relayed > 1000)
  {
    packet.from.relayed = Date.now();
    packet.from.relays = 0;
  }

  packet.from.relays++;

  if(packet.from.relays > 5){
    logger.debug('relay too fast, dropping',packet.from.relays);
    return;
  }

  // dumb relay
  logger.debug('relay middleman',packet.from.hashname,to.hashname);

  packet.from.relayed = Date.now();
  to.send(packet);
}

// someone's trying to connect to us, send an open to them
function inConnect(err, packet, chan)
{
  if(!packet.body){
    return;
  }

  var self = packet.from.self;
  var der = local.der2der(packet.body);
  var to = self.whois(local.der2hn(der));

  if(!to){
    logger.warn('invalid connect request from',packet.from.address,packet.js);
    return;
  }

  to.der = der;
  var sentOpen = to.sentOpen;

  // try the suggested paths
  if(Array.isArray(packet.js.paths)) packet.js.paths.forEach(function(path){

    if(typeof path.type != 'string'){
      return logger.debug('bad path',JSON.stringify(path));
    }

    // store any path as a possible one
    to.possible[path.type] = path;

    // if they are offering to provide assistance, stash the sender
    if(['bridge','relay'].indexOf(path.type) >= 0){
      path.via = packet.from.hashname;
    }

    // ignore types that you can't send to directly until you have a line
    if(['bridge','webrtc'].indexOf(path.type) >= 0){
      return;
    }

    to.sentOpen = sentOpen; // restore throttling var since these are all bunched together, could be refactored better as a batch
    to.open(path);
  });
  
  // if we didn't send any, no valid paths, always try a relay
  if(to.sentOpen == sentOpen){
    to.open({
      type:'relay',
      id:local.randomHEX(16),
      via:packet.from.hashname
    });
  }
}

// be the middleman to help NAT hole punch
function inPeer(err, packet, chan)
{
  if(!utilities.isHEX(packet.js.peer, 64)){
    return;
  }

  var self = packet.from.self;

  var peer = self.whois(packet.js.peer);

  if(!peer.lineIn){
    return; // these happen often as lines come/go, ignore dead peer requests
  }

  // send a single lossy packet
  var js = {
    type:'connect',
    end:true,
    c:local.randomHEX(16)
  };

  // sanity on incoming paths array
  if(!Array.isArray(packet.js.paths)){
    packet.js.paths = [];
  }
  
  // insert in incoming IP path, TODO refactor how we overload paths, poor form
  if(packet.sender.type.indexOf('ip') === 0){
    var path = JSON.parse(JSON.stringify(packet.sender)); // clone
    delete path.priority;
    delete path.lastIn;
    delete path.lastOut;
    packet.js.paths.push(path);
  }
  
  // load/cleanse all paths
  js.paths = [];
  var hasRelay;
  packet.js.paths.forEach(function(path){

    if(typeof path.type != 'string'){
      return;
    }

    if(path.type == 'relay' && packet.sender.type == 'relay'){
      return; // don't signal double-relay
    }

    if(path.type.indexOf('ip') === 0 && utilities.isLocalIP(path.ip) && !peer.isLocal){
      return; // don't pass along local paths to public
    }

    if(path.type == 'relay'){
      hasRelay = true;
    }

    js.paths.push(path);
  });

  // look for a "viable" IP path between the two
  var viable = false;
  js.paths.forEach(function(path1){
    peer.paths.forEach(function(path2){

      if(path1.type != path2.type){
        return;
      }
      if(path1.type.indexOf('ip') !== 0){
        return; // only IP paths
      }
      if(utilities.isLocalIP(path1.ip) != utilities.isLocalIP(path2.ip)){
        return; // must both be local or public
      }
      viable = [path1,path2];
    });
  });

  logger.debug('peer viable path results',JSON.stringify(viable));

  // when no viable path, always offer to bridge/relay
  if(!viable)
  {

    peer.bridging = true;

    js.paths.push({
      type:'bridge',
      id:packet.from.hashname,
      local:true
    });

    // add relay if none yet, and isn't via one already
    if(!hasRelay && packet.sender.type != 'relay'){
      js.paths.push({
        type:'relay',
        id:local.randomHEX(16)
      });
    }
  }
  
  // must bundle the senders der so the recipient can open them
  peer.send({js:js, body:packet.from.der});
}


exports.receive = receive;
exports.inSeek = inSeek;
exports.inPath = inPath;
exports.inRelayMe = inRelayMe;
exports.inRelay = inRelay;
exports.inTS = inTS;
exports.inPeer = inPeer;
exports.inConnect = inConnect;
exports.inBridge = inBridge;