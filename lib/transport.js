'use strict';

var logger = require('./logging');
var utilities = require('./utilities');
var locals = require('./locals');
var bucket = require('./bucket');
var defaults = require('./defaults');

// hackjib
// dependency functions
var local = locals.local;

// these are called once a reliable channel is started both ways to add custom functions for the app
var channelWraps = {
  'stream':function(chan){
    // send raw data over, must not be called again until cbMore(err) is called
    chan.write = function(data, cbMore){
      // break data into chunks
      // if outgoing is full, chan.more = cbMore
    };
    chan.callback = function(packet, callback){
      if(!chan.read){
        return chan.end('no handler');
      }
      // TODO if chan.more and outgoing isn't full, var more=chan.more;delete chan.more;more()
      if(!packet.body && !packet.js.end){
        return callback(); // odd empty?
      }
      chan.read(packet.js.err||packet.js.end, packet.body, callback);
    };
  },
  'bulk':function(chan){
    // handle any incoming bulk flow
    var bulkIn = '';
    chan.callback = function(end, packet, chan, cb){
      cb();
      if(packet.body){
        bulkIn += packet.body;
      }
      if(!chan.onBulk){
        return;
      }
      if(end){
        chan.onBulk(end!==true?end:false, bulkIn);
      }
    };
    // handle (optional) outgoing bulk flow
    chan.bulk = function(data, callback){
      // break data into chunks and send out, no backpressure yet
      while(data)
      {
        var chunk = data.substr(0,1000);
        data = data.substr(1000);
        var packet = {body:chunk};
        if(!data){
          packet.callback = callback; // last packet gets confirmed
        }
        chan.send(packet);
      }
      chan.end();
    };
  },
  'TS':function(chan){
    chan.socket = {
      data:'',
      hashname:chan.hashname,
      id:chan.id
    };
    chan.callback = function(err, packet, chan, callback){
      // go online
      if(chan.socket.readyState === 0)
      {
        chan.socket.readyState = 1;
        if(chan.socket.onopen){
          chan.socket.onopen();
        }
      }
      if(packet.body){
        chan.socket.data += packet.body;
      }
      if(packet.js.done)
      {
        // allow ack-able onmessage handler instead
        if(chan.socket.onmessageack){
          chan.socket.onmessageack(chan.socket, callback);
        }
        else{
          callback();
        }
        if(chan.socket.onmessage){
          chan.socket.onmessage(chan.socket);
        }
        chan.socket.data = '';
      }else{
        callback();
      }
      if(err)
      {
        chan.socket.readyState = 2;
        if(err !== true && chan.socket.onerror){
          chan.socket.onerror(err);
        }
        if(chan.socket.onclose) chan.socket.onclose();
      }
    };
    // set up TS object for external use
    chan.socket.readyState = chan.lastIn ? 1 : 0; // if channel was already active, set state 1
    chan.socket.send = function(data, callback){
      if(chan.socket.readyState != 1){
        return logger.debug('sending fail to TS readyState',chan.socket.readyState)&&false;
      }
      // chunk it
      while(data)
      {
        var chunk = data.substr(0,1000);
        data = data.substr(1000);
        var packet = {js:{},body:chunk};
        // last packet gets confirmed/flag
        if(!data)
        {
          packet.callback = callback;
          packet.js.done = true;
        }
        logger.debug('TS SEND',chunk.length,packet.js.done);
        chan.send(packet);
      }
    };
    chan.socket.close = function(){
      chan.socket.readyState = 2;
      chan.done();
    };
  }
};

// self.receive, raw incoming udp data
function receive(msg, path)
{
  /*jshint validthis: true */
	var self = this;
  var packet = local.pdecode(msg);
  if(!packet){
    return logger.warn('failed to decode a packet from', path, msg.toString());
  }
  if(Object.keys(packet.js).length === 0){
    return; // empty packets are NAT pings
  }
  
  packet.sender = path;
  packet.id = self.pcounter++;
  packet.at = Date.now();
  if(typeof msg.length == 'function'){
    logger.debug('in',msg.length());
  }else{
    logger.debug('in',msg.length, packet.js.type, packet.body && packet.body.length,JSON.stringify(path));
  }

  // handle any LAN notifications
  if(packet.js.type == 'lan'){
    return inLan(self, packet);
  }
  if(packet.js.type == 'seed'){
    return inLanSeed(self, packet);
  }

  if(typeof packet.js.iv != 'string' || packet.js.iv.length != 32){
    return logger.warn('missing initialization vector (iv)', path);
  }

  var line = {};

  // either it's an open
  if(packet.js.type == 'open')
	{
    var open = local.deopenize(self, packet);
    if (!open || !open.verify){
      return logger.warn('couldn\'t decode open',open);
    }
    if (!utilities.isHEX(open.js.line, 32)){
      return logger.warn('invalid line id enclosed',open.js.line);
    }
    if(open.js.to !== self.hashname){
      return logger.warn('open for wrong hashname',open.js.to);
    }

    var from = self.whois(local.der2hn(open.rsa));
    if (!from){
      return logger.warn('invalid hashname', local.der2hn(open.rsa), open.rsa);
    }

    // make sure this open is newer (if any others)
    if (typeof open.js.at != 'number'){
      return logger.warn('invalid at', open.js.at);
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
    bucket.bucketize(self, from); // add to their bucket
    
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

    return;
	}

  // or it's a line
  if(packet.js.type == 'line')
	{
	  line = packet.from = self.lines[packet.js.line];

	  // a matching line is required to decode the packet
	  if(!line) {
	    if(!self.bridges[packet.js.line]){
        return logger.debug('unknown line received', packet.js.line, JSON.stringify(packet.sender));
      }
      logger.debug('BRIDGE',JSON.stringify(self.bridges[packet.js.line]),packet.js.line);
      if(self.bridgeIVs[packet.js.iv]){
        return; // drop duplicates
      }
      self.bridgeIVs[packet.js.iv] = true;
      // flat out raw retransmit any bridge packets
      return self.send(self.bridges[packet.js.line],msg);
	  }

		// decrypt and process
	  local.delineize(packet);
		if(!packet.lineok){
      return logger.debug('couldn\'t decrypt line',packet.sender);
    }
    line.receive(packet);
    return;
	}
  
  if(Object.keys(packet.js).length > 0){
    logger.warn('dropping incoming packet of unknown type', packet.js, packet.sender);
  }
}

// type lan, looking for a local seed
function inLan(self, packet)
{
  if(packet.js.lan == self.lanToken) return; // ignore ourselves
  if(self.locals.length > 0) return; // someone locally is announcing already
  if(self.lanSkip == self.lanToken) return; // often immediate duplicates, skip them
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

// every line that needs to be maintained, ping them
function meshPing(self)
{
  Object.keys(self.lines).forEach(function(line){
    var hn = self.lines[line];
    // have to be elected or a line with a channel open (app)
    if(!(hn.elected || Object.keys(hn.chans).length > 0)){
      return;
    }
    // don't ping unless we'll go past the timeout
    if(((Date.now() - hn.sentAt) + defaults.mesh_timer) < hn.timeout()){
      return;
    }
    // seek ourself to discover any new hashnames closer to us for the buckets, used recursively
    function ping(to)
    {
      logger.debug('mesh ping',to.bucket,to.hashname);
      to.raw('seek', {
        js:{
          'seek':self.hashname
        }, timeout:3000}, function(err, packet){
          if(!Array.isArray(packet.js.see)){
            return;
          }
          // load any sees to look for potential bucket candidates
          packet.js.see.forEach(function(address){
            var sug = self.whois(address);
            if(!sug){
              return;
            }
            sug.via(to, address);
            if(sug === self || sug.bucket){
              return; // already bucketized
            }
            // if their bucket has capacity, ping them
            sug.bucket = utilities.dhash(self.hashname, hn.hashname);
            if(self.capacity[sug.bucket] === undefined){
              self.capacity[sug.bucket] = 3; // safe default for a new bucket
            }
            if(self.capacity[sug.bucket]-- >= 0){
              ping(sug);
            }
          });
      });
    }
    ping(hn);
  });
}

// return a see to anyone closer
function inSeek(err, packet, chan)
{
  if(err){
    return;
  }
  if(!utilities.isHEX(packet.js.seek, 64)){
    return logger.warn('invalid seek of ', packet.js.seek, 'from:', packet.from.address);
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
  chan.send({js:answer});
}

// update/respond to network state
function inPath(err, packet, chan)
{
  // check/try any alternate paths
  if(Array.isArray(packet.js.paths)){
    packet.js.paths.forEach(function(path){
      if(typeof path.type != 'string'){
        return; // invalid
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
  if(err){
    return; // bye bye bye!
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
    return logger.warn('invalid bridge request',JSON.stringify(packet.js),packet.from.hashname);
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
        if(!local) local = path;
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
  if(err) return; // TODO clean up anything?
  if(!packet.body){
    return logger.warn('relay in w/ no body',packet.js,packet.from.address);
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
    return logger.warn('invalid relay of', packet.js.to, 'from', packet.from.address);
  }

  // if it's to us, handle that directly
  if(packet.js.to == self.hashname){
    return inRelayMe(err, packet, chan);
  }

  // don't relay when it's coming from a relay
  if(packet.sender.type == 'relay'){
    return logger.debug('ignoring relay request from a relay',packet.js.to,JSON.stringify(packet.sender));
  }

  // if to someone else
  var to = self.whois(packet.js.to);
  if(to === packet.from){
    return logger.warn('can\'t relay to yourself',packet.from.hashname);
  }
  if(!to || !to.alive){
    return logger.warn('relay to dead hashname', packet.js.to, packet.from.address);
  }

  // throttle
  if(!packet.from.relayed || Date.now() - packet.from.relayed > 1000)
  {
    packet.from.relayed = Date.now();
    packet.from.relays = 0;
  }
  packet.from.relays++;
  if(packet.from.relays > 5){
    return logger.debug('relay too fast, dropping',packet.from.relays);
  }

  // dumb relay
  logger.debug('relay middleman',packet.from.hashname,to.hashname);
  packet.from.relayed = Date.now();
  to.send(packet);
}

// create a reliable channel with a friendlier interface
function channel(type, arg, callback)
{
  /*jshint validthis: true */
  var hn = this;
  var chan = {
    inq:[],
    outq:[],
    outSeq:0,
    inDone:-1,
    outConfirmed:-1,
    lastAck:-1,
    callback:callback
  };
  chan.id = arg.id || local.randomHEX(16);
  hn.chans[chan.id] = chan;
  chan.timeout = arg.timeout || defaults.chan_timeout;
  // app originating if no id, be friendly w/ the type, don't double-underscore if they did already
  if(!arg.id && type.substr(0,1) !== '_'){
    type = '_'+type;
  }
  chan.type = type; // save for debug
  if(chan.type.substr(0,1) != '_'){
    chan.safe = true; // means don't _ escape the json
  }
  chan.hashname = hn.hashname; // for convenience

  logger.debug('new channel',hn.hashname,chan.type,chan.id);

  // used by app to change how it interfaces with the channel
  chan.wrap = function(wrap)
  {
    var chan = this;
    if(!channelWraps[wrap]){
      return false;
    }
    channelWraps[wrap](chan);
    return chan;
  };

  // called to do eventual cleanup
  chan.done = function(){
    if(chan.ended){
      return; // prevent multiple calls
    }
    chan.ended = true;
    logger.debug('channel done',chan.id);
    setTimeout(function(){
      // fire .callback(err) on any outq yet?
      delete hn.chans[chan.id];
    }, chan.timeout);
  };

  // used to internally fail a channel, timeout or connection failure
  chan.fail = function(packet){
    if(chan.errored){
      return; // prevent multiple calls
    }
    chan.errored = packet;
    chan.callback(packet.js.err, packet, chan, function(){});
    chan.done();
  };

  // simple convenience wrapper to end the channel
  chan.end = function(){
    chan.send({
      end:true
    });
  };

  // errors are hard-send-end
  chan.err = function(err){
    if(chan.errored){
      return;
    }
    chan.errored = {
      js:{
        err:err,
        c:chan.id
      }
    };
    hn.send(chan.errored);
    chan.done();
  };

  // process packets at a raw level, handle all miss/ack tracking and ordering
  chan.receive = function(packet)
  {
    // if it's an incoming error, bail hard/fast
    if(packet.js.err){
      return chan.fail(packet);
    }

    // in errored state, only/always reply with the error and drop
    if(chan.errored){
      return chan.send(chan.errored);
    }
    if(!packet.js.end){
      chan.lastIn = Date.now();
    }

    // process any valid newer incoming ack/miss
    var ack = parseInt(packet.js.ack);
    if(ack > chan.outSeq){
      return logger.warn('bad ack, dropping entirely',chan.outSeq,ack);
    }
    var miss = Array.isArray(packet.js.miss) ? packet.js.miss : [];
    if(miss.length > 100){
      logger.warn('too many misses', miss.length, chan.id, packet.from.address);
      miss = miss.slice(0,100);
    }
    if(miss.length > 0 || ack > chan.lastAck){
      logger.debug('miss processing',ack,chan.lastAck,miss,chan.outq.length);
      chan.lastAck = ack;
      // rebuild outq, only keeping newer packets, resending any misses
      var outq = chan.outq;
      chan.outq = [];
      outq.forEach(function(pold){
        // packet acknowleged!
        if(pold.js.seq <= ack) {
          if(pold.callback){
            pold.callback();
          }
          return;
        }
        chan.outq.push(pold);
        if(miss.indexOf(pold.js.seq) == -1){
          return;
        }
        // resend misses but not too frequently
        if(Date.now() - pold.resentAt < 1000){
          return;
        }
        pold.resentAt = Date.now();
        chan.ack(pold);
      });
    }
    
    // don't process packets w/o a seq, no batteries included
    var seq = packet.js.seq;
    if(seq < 0){
      return;
    }

    // auto trigger an ack in case none were sent
    if(!chan.acker){
      chan.acker = setTimeout(function(){
        delete chan.acker;
        chan.ack();
      }, defaults.chan_autoack);
    }

    // drop duplicate packets, always force an ack
    if(seq <= chan.inDone || chan.inq[seq-(chan.inDone+1)]){
      chan.forceAck = true;
      return true;
    }
  
    // drop if too far ahead, must ack
    if(seq-chan.inDone > defaults.chan_inbuf)
    {
      logger.warn('chan too far behind, dropping', seq, chan.inDone, chan.id, packet.from.address);
      chan.forceAck = true;
      return true;
    }

    // stash this seq and process any in sequence, adjust for yacht-based array indicies
    chan.inq[seq-(chan.inDone+1)] = packet;
    logger.debug('INQ',Object.keys(chan.inq),chan.inDone,chan.handling);
    chan.handler();
  };
  
  // wrapper to deliver packets in series
  chan.handler = function()
  {
    if(chan.handling){
      return;
    }
    var packet = chan.inq[0];
    // always force an ack when there's misses yet
    if(!packet && chan.inq.length > 0){
      chan.forceAck = true;
    }
    if(!packet){
      return;
    }
    chan.handling = true;
    if(!chan.safe){
      packet.js = packet.js._ || {}; // unescape all content json
    }
    chan.callback(packet.js.end, packet, chan, function(){
      chan.inq.shift();
      chan.inDone++;
      chan.handling = false;
      chan.handler();
    });
  };
  
  // resend the last sent packet if it wasn't acked
  chan.resend = function()
  {
    if(chan.ended){
      return;
    }
    if(!chan.outq.length){
      return;
    }
    var lastpacket = chan.outq[chan.outq.length-1];
    // timeout force-end the channel
    if(Date.now() - lastpacket.sentAt > chan.timeout)
    {
      chan.fail({
        js:{
          err:'timeout'
        }
      });
      return;
    }
    logger.debug('channel resending');
    chan.ack(lastpacket);
    setTimeout(chan.resend, defaults.chan_resend); // recurse until chan_timeout
  };

  // add/create ack/miss values and send
  chan.ack = function(packet)
  {
    if(!packet){
      logger.debug('ACK CHECK',chan.id,chan.outConfirmed,chan.inDone);
    }

    // these are just empty "ack" requests
    if(!packet)
    {
      // drop if no reason to ack so calling .ack() harmless when already ack'd
      if(!chan.forceAck && chan.outConfirmed == chan.inDone){
        return;
      }
      packet = {
        js:{

        }
      };
    }
    chan.forceAck = false;
    
    // confirm only what's been processed
    if(chan.inDone >= 0){
      chan.outConfirmed = packet.js.ack = chan.inDone;
    }

    // calculate misses, if any
    delete packet.js.miss; // when resending packets, make sure no old info slips through
    if(chan.inq.length > 0)
    {
      packet.js.miss = [];
      for(var i = 0; i < chan.inq.length; i++)
      {
        if(!chan.inq[i]){
          packet.js.miss.push(chan.inDone+i+1);
        }
      }
    }
    
    // now validate and send the packet
    packet.js.c = chan.id;
    logger.debug('SEND',chan.type,JSON.stringify(packet.js));
    hn.send(packet);

    // catch whenever it was ended to start cleanup
    if(packet.js.end){
      chan.done();
    }
  };

  // send content reliably
  chan.send = function(arg)
  {
    if(chan.ended){
      return logger.warn('can\'t send to an ended channel');
    }

    // create a new packet from the arg
    if(!arg) arg = {};
    var packet = {};
    packet.js = chan.safe ? arg.js : {_:arg.js};
    if(arg.type) packet.js.type = arg.type;
    if(arg.end) packet.js.end = arg.end;
    packet.body = arg.body;
    packet.callback = arg.callback;

    // do durable stuff
    packet.js.seq = chan.outSeq++;

    // reset/update tracking stats
    packet.sentAt = Date.now();
    chan.outq.push(packet);
    
    // add optional ack/miss and send
    chan.ack(packet);

    // to auto-resend if it isn't acked
    if(chan.resender) clearTimeout(chan.resender);
    chan.resender = setTimeout(chan.resend, defaults.chan_resend);
    return chan;
  };
  
  // send optional initial packet with type set
  if(arg.js)
  {
    arg.type = type;
    chan.send(arg);
  }

  return chan;
}

// create an unreliable channel
function raw(type, arg, callback)
{
  /*jshint validthis: true */
  var hn = this;
  var chan = {type:type, callback:callback};
  chan.id = arg.id || local.randomHEX(16);
  hn.chans[chan.id] = chan;
  
  // raw channels always timeout/expire after the last sent/received packet
  chan.timeout = arg.timeout||defaults.chan_timeout;
  function timer()
  {
    if(chan.timer){
      clearTimeout(chan.timer);
    }
    chan.timer = setTimeout(function(){
      if(!hn.chans[chan.id]){
        return; // already gone
      }
      delete hn.chans[chan.id];
      chan.callback('timeout',{
        js:{
          err:'timeout'
        }
      },chan);
    }, chan.timeout);
  }

  chan.hashname = hn.hashname; // for convenience

  logger.debug('new unreliable channel',hn.hashname,chan.type,chan.id);

  // process packets at a raw level, very little to do
  chan.receive = function(packet)
  {
    // if err'd or ended, delete ourselves
    if(packet.js.err || packet.js.end){
      delete hn.chans[chan.id];
    }
    chan.last = packet.sender; // cache last received network
    chan.callback(packet.js.err||packet.js.end, packet, chan);
    timer();
  };

  // minimal wrapper to send raw packets
  chan.send = function(packet)
  {
    if(!packet.js){
      packet.js = {};
    }
    packet.js.c = chan.id;
    logger.debug('SEND',chan.type,JSON.stringify(packet.js));
    if(!packet.to && chan.last){
      packet.to = chan.last; // always send back to the last received for this channel
    }
    hn.send(packet);
    // if err'd or ended, delete ourselves
    if(packet.js.err || packet.js.end){
      delete hn.chans[chan.id];
    }
    timer();
  };
  
  // dummy stub
  chan.fail = function(){

  };

  // send optional initial packet with type set
  if(arg.js)
  {
    arg.js.type = type;
    chan.send(arg);
  }
  
  return chan;
}

// every 25 seconds do the maintenance work for peers
function meshLoop(self)
{
  self.bridgeIVs = {}; // reset IV cache for any bridging
  logger.debug('MESHA');
  //meshReap(self); // remove any dead ones, temporarily disabled due to node crypto compiled cleanup bug
  meshElect(self); // which ones go into buckets
  meshPing(self); // ping all of them
  logger.debug('MESHZ');
  setTimeout(function(){
    meshLoop(self);
  }, defaults.mesh_timer);
}

// delete any defunct hashnames!
function meshReap(self)
{
  var hn;
  function del(why)
  {
    if(hn.lineOut){
      delete self.lines[hn.lineOut];
    }
    delete self.all[hn.hashname];
    logger.debug('reaping ', hn.hashname, why);
  }
  Object.keys(self.all).forEach(function(h){
    hn = self.all[h];
    logger.debug('reap check',hn.hashname,Date.now()-hn.sentAt,Date.now()-hn.recvAt,Object.keys(hn.chans).length);
    if(hn.isSeed){
      return;
    }
    if(Object.keys(hn.chans).length > 0){
      return; // let channels clean themselves up
    }
    if(Date.now() - hn.at < hn.timeout()){
      return; // always leave n00bs around for a while
    }
    if(!hn.sentAt){
      return del('never sent anything, gc');
    }
    if(!hn.recvAt){
      return del('sent open, never received');
    }
    if(Date.now() - hn.sentAt > hn.timeout()){
      return del('we stopped sending to them');
    }
    if(Date.now() - hn.recvAt > hn.timeout()){
      return del('they stopped responding to us');
    }
  });
}

// update which lines are elected to keep, rebuild self.buckets array
function meshElect(self)
{
  // sort all lines into their bucket, rebuild buckets from scratch (some may be GC'd)
  self.buckets = []; // sparse array, one for each distance 0...255
  self.capacity = [];
  Object.keys(self.lines).forEach(function(line){
    bucket.bucketize(self, self.lines[line]);
  });
  logger.debug('BUCKETS',Object.keys(self.buckets));
  var spread = parseInt(defaults.mesh_max / Object.keys(self.buckets).length);
  if(spread <= 1){
    spread = 1;
  }

  // each bucket only gets so many lines elected
  Object.keys(self.buckets).forEach(function(bucket){
    var elected = 0;
    self.buckets[bucket].forEach(function(hn){
      if(!hn.alive){
        return;
      }
      // TODO can use other health quality metrics to elect better/smarter ones
      hn.elected = (elected++ <= spread) ? true : false;
    });
    self.capacity[bucket] = spread - elected; // track any capacity left per bucket
  });
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
    return logger.warn('invalid connect request from',packet.from.address,packet.js);
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
exports.meshPing = meshPing;
exports.inSeek = inSeek;
exports.inPath = inPath;
exports.inRelayMe = inRelayMe;
exports.inRelay = inRelay;
exports.channel = channel;
exports.raw = raw;
exports.meshLoop = meshLoop;
exports.inTS = inTS;
exports.inPeer = inPeer;
exports.inConnect = inConnect;
exports.inBridge = inBridge;
exports.channelWraps = channelWraps;