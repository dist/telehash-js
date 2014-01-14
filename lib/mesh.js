'use strict';

var logger = require('./logging');
var utilities = require('./utilities');
var bucket = require('./bucket');
var defaults = require('./defaults');

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
    ping(self,hn,hn);
  });
}

// send ping
function ping(self,to,hn)
{
  logger.debug('mesh ping',to.bucket,to.hashname);

  to.raw('seek', {
    js:{
      'seek':self.hashname
    }, timeout:3000
  }, function(err, packet){

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

        // already bucketized
        if(sug === self || sug.bucket){
          return;
        }

        // if their bucket has capacity, ping them
        sug.bucket = utilities.dhash(self.hashname, hn.hashname);

        // safe default for a new bucket
        if(self.capacity[sug.bucket] === undefined){
          self.capacity[sug.bucket] = 3;
        }

        if(self.capacity[sug.bucket]-- >= 0){
          ping(self,sug,hn);
        }

      });
  });
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
      del('never sent anything, gc');
      return;
    }
    if(!hn.recvAt){
      del('sent open, never received');
      return;
    }
    if(Date.now() - hn.sentAt > hn.timeout()){
      del('we stopped sending to them');
      return;
    }
    if(Date.now() - hn.recvAt > hn.timeout()){
      del('they stopped responding to us');
      return;
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

exports.meshPing = meshPing;
exports.meshLoop = meshLoop;