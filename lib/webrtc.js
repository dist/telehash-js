'use strict';
/*global thweb:true,forge:true,me:true*/
/*jshint browser:true*/

// this file contains browser-only support functions for running telehash there
// primarily it has webrtc networking based on code from https://github.com/natevw

(function(exports) {
  
  // rtc is a little wrapper to interface to an active switch to create a webrtc channel
  function rtc(sw, arg)
  {
    var RTC = arg;

    // dummy function to cache last packet
    RTC.send = function(data){
      RTC.cached = data;
    };

    // either create a channel to them and init it
    if(!RTC.chan){
      sw.whois(RTC.to).start('webrtc', {
        id:RTC.id,
        js:{

        }
      }, function(err, packet, chan, cb) {
        cb();
        if (err){
          return console.log('rtc error', err);
        }
        RTC.chan = chan;
        init(RTC,sw,true);
      });
    }

    // or we got a channel passed in, wait for signal
    if(RTC.chan){
      init(RTC,sw,false);
    }

    return RTC;
  }

  // initialize pch when needed
  function init(RTC,sw,flag) {

    RTC.chan.wrap('TS');
    RTC.pch = new thweb.pch({initiate:flag, _self:sw.hashname, _peer:RTC.chan.hashname});
    RTC.pch.DEBUG = true;

    RTC.chan.socket.onmessage = function(data) {
      console.log('RTC IN', data);
      try {
        data = JSON.parse(data.data);
      } catch (E) {
        console.log('rtc parse error', E, data.data);
        return;
      }
      RTC.pch.receiveSignal(data);
    };

    RTC.pch.onhavesignal = function(evt) {
      console.log('RTC OUT', evt.signal, RTC.chan.socket);
      RTC.chan.socket.send(JSON.stringify(evt.signal));
    };

    RTC.pch.onconnection = function() {
      console.log('RTC CONNECTED');
      RTC.send = function(data){
        RTC.pch.sendMessage(forge.util.encode64(data));
      };
      if(RTC.cached)
      {
        RTC.send(RTC.cached);
        delete RTC.cached;
      }
    };

    RTC.pch.onreceivemessage = function(msg) {
      if(msg && msg.data){
        me.receive(forge.util.decode64(msg.data),{
          type:'webrtc',
          id:RTC.id
        });
      }
    };

  }

  // PeerConnectionHandler extracted from code in https://github.com/natevw/PeerPouch
  var RTCPeerConnection = window.mozRTCPeerConnection || window.RTCPeerConnection || window.webkitRTCPeerConnection,
    RTCSessionDescription = window.mozRTCSessionDescription || window.RTCSessionDescription || window.webkitRTCSessionDescription,
    RTCIceCandidate = window.mozRTCIceCandidate || window.RTCIceCandidate || window.webkitRTCIceCandidate;

  // add optional webrtc network support to a switch
  function rtcAdd(sw, conns){

    if(!RTCPeerConnection){
      return console.log('WebRTC support not found, disabled');
    }

    console.log('enabling WebRTC support');
    sw.paths.webrtc = true;
    sw.rels.webrtc = function(err, arg, chan, cb) {
      cb();
      chan.send({
        js:{
          open:true
        }
      });
      conns[chan.id] = thweb.rtc(me, {
        chan:chan,
        id:chan.id
      });
    };
  }

  function PeerConnectionHandler(opts) {
    if(!opts){
      opts = {};
    }
    opts.reliable = true;
    var cfg = {
      'iceServers': [{
        'url': 'stun:23.21.150.121'
      }]
    },
    con = (opts.reliable) ? {} : {
      'optional': [{
        'RtpDataChannels': true
      }]
    };

    this._rtc = new RTCPeerConnection(cfg, con);

    this.LOG_SELF = opts._self;
    this.LOG_PEER = opts._peer;
    this._channel = null;

    this.onhavesignal = null; // caller MUST provide this
    this.onreceivemessage = null; // caller SHOULD provide this
    this.onconnection = null; // …and maybe this

    var handler = this,
    rtc = this._rtc;

    if (opts.initiate){
      this._setupChannel();
    }
    else{
      rtc.ondatachannel = this._setupChannel.bind(this);
    }

    rtc.onnegotiationneeded = function(evt) {

      if (handler.DEBUG){
        console.log(handler.LOG_SELF, 'saw negotiation trigger and will create an offer');
      }

      rtc.createOffer(function(offerDesc) {
        if(handler.DEBUG){
          console.log(handler.LOG_SELF, 'created offer, sending to', handler.LOG_PEER);
        }

        rtc.setLocalDescription(offerDesc, function() {
          console.log('DONE');
        });

        handler._sendSignal(offerDesc);
      }, function(e) {
        console.warn(handler.LOG_SELF, 'failed to create offer', e);
      });
    };

    rtc.onicecandidate = function(evt) {
      if (evt.candidate) handler._sendSignal({
        candidate: evt.candidate
      });
    };

    // debugging
    rtc.onicechange = function(evt) {
      if(handler.DEBUG){
        console.log(handler.LOG_SELF, 'ICE change', rtc.iceGatheringState, rtc.iceConnectionState);
      }
    };

    rtc.onstatechange = function(evt) {
      if(handler.DEBUG){
        console.log(handler.LOG_SELF, 'State change', rtc.signalingState, rtc.readyState);
      }
    };
  }

  PeerConnectionHandler.prototype._sendSignal = function(data) {

    if(!this.onhavesignal){
      throw new Error('Need to send message but `onhavesignal` handler is not set.');
    }

    this.onhavesignal({
      target: this,
      signal: JSON.parse(JSON.stringify(data))
    });
  };

  PeerConnectionHandler.prototype.receiveSignal = function(data) {

    var handler = this,
    rtc = this._rtc;

    if (handler.DEBUG){
      console.log(this.LOG_SELF, 'got data', data, 'from', this.LOG_PEER);
    }

    if(data.sdp){
      rtc.setRemoteDescription(new RTCSessionDescription(data), function() {
        var needsAnswer = (rtc.remoteDescription.type == 'offer');

        if(handler.DEBUG){
          console.log(handler.LOG_SELF, 'set offer, now creating answer:', needsAnswer);
        }

        if(needsAnswer){
          rtc.createAnswer(function(answerDesc) {

            if(handler.DEBUG){
              console.log(handler.LOG_SELF, 'got anwer, sending back to', handler.LOG_PEER);
            }

            rtc.setLocalDescription(answerDesc);
            handler._sendSignal(answerDesc);
          }, function(e) {
            console.warn(handler.LOG_SELF, 'couldn\'t create answer', e);
          });
        }
      }, function(e) {
        console.warn(handler.LOG_SELF, 'couldn\'t set remote description', e);
      });
    }
    else if(data.candidate){
      try {
        rtc.addIceCandidate(new RTCIceCandidate(data.candidate));
      }catch (e) {
        console.error('Couldn\'t add candidate', e);
      }
    }
  };

  PeerConnectionHandler.prototype.sendMessage = function(data) {
    var handler = this;
    if(!this._channel || this._channel.readyState !== 'open'){
      if(handler.DEBUG){
        console.log('dropping data, no open channel');
      }
      return;
    }
    this._channel.send(data);
  };

  PeerConnectionHandler.prototype._setupChannel = function(evt) {
    var handler = this,
    rtc = this._rtc;
    if(evt){
      if(handler.DEBUG){
        console.log(this.LOG_SELF, 'received data channel', evt.channel.readyState);
      }
    }
    this._channel = (evt) ? evt.channel : rtc.createDataChannel('telehash');
    // NOTE: in Chrome (M32) `this._channel.binaryType === 'arraybuffer'` instead of blob

    this._channel.onopen = function(evt) {
      if(handler.DEBUG){
        console.log(handler.LOG_SELF, 'DATA CHANNEL IS OPEN', handler._channel);
      }

      if(handler.onconnection){
        handler.onconnection(handler._channel); // BOOM!
      }
    };

    this._channel.onmessage = function(evt) {
      if(handler.DEBUG){
        console.log(handler.LOG_SELF, 'received message!', evt);
      }
      if(handler.onreceivemessage){
        handler.onreceivemessage({
          target: handler,
          data: evt.data
        });
      }
    };

    if (window.mozRTCPeerConnection){
      setTimeout(function() {
        rtc.onnegotiationneeded(); // FF doesn't trigger this for us like Chrome does
      }, 0);
    }
    window.dbgChannel = this._channel;
  };

  PeerConnectionHandler.prototype._tube = function() { // TODO: refactor PeerConnectionHandler to simply be the "tube" itself
    var tube = {},
    handler = this;
    tube.onmessage = null;
    tube.send = function(data) {
      handler.sendMessage(data);
    };
    handler.onreceivemessage = function(evt) {
      if(tube.onmessage){
        tube.onmessage(evt);
      }
    };
    return tube;
  };

  // exported functions
  exports.pch = PeerConnectionHandler;
  exports.rtc = rtc;
  exports.rtcAdd = rtcAdd;

})((typeof exports == 'undefined') ? (this.thweb = {}) : exports);
