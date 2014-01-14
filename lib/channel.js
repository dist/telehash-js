'use strict';

var defaults = require('./defaults');
var logger = require('./logging');
var locals = require('./locals');

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

// create a reliable channel with a friendlier interface
function channel(type, arg, callback)
{
  /*jshint validthis: true */
  var hn = this;

  var chan = {
    id : arg.id || local.randomHEX(16),
    inq : [],
    outq : [],
    outSeq : 0,
    inDone : -1,
    outConfirmed : -1,
    lastAck : -1,
    callback : callback
  };

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

exports.channel = channel;
exports.raw = raw;
exports.channelWraps = channelWraps;