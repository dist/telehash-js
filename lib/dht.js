'use strict';

var logger = require('./logging');
var utilities = require('./utilities');

// try to create a bridge to them
function bridge(to, callback)
{
  /*jshint validthis: true */
  var self = this;
  logger.debug('trying to start a bridge',to.hashname,JSON.stringify(to.possible));
  if(Object.keys(to.possible).length === 0){
    return callback(); // no possible paths to bridge to
  }
  var found;
  function start(via, path)
  {
    // try to find a better path type we know the bridge supports
    if(!path){
      via.paths.forEach(function(p){
        if(!path || to.possible[p.type]){
          path = to.possible[p.type];
        }
      });
    }
    via.raw('bridge', {
      js:{
        to:to.lineIn,
        from:to.lineOut,
        path:path
      }
    }, function(end, packet){
      // TODO we can try another path and/or via?
      if(end !== true){
        logger.debug('failed to create bridge',end,via.hashname);
      }
      if(end){
        callback(packet.sender,via);
      }else{
        callback(false, via);
      }
    });
  }
  // if there's a bridge volunteer for them already
  if(to.possible.bridge && to.possible.bridge.via){
    return start(self.whois(to.possible.bridge.via), to.possible.bridge);
  }
  // find any bridge supporting seed
  Object.keys(self.seeds).forEach(function(seed){
    if(found){
      return;
    }
    seed = self.seeds[seed];
    if(!seed.alive || !seed.bridging){
      return;
    }
    found = true;
    start(seed);
  });

  // worst case, blind attempt to bridge through the relay
  if(!found && to.relay){
    return start(self.whois(to.relay.via));
  }

  if(!found){
    return callback();
  }
}
// when we get a via to ourselves, check address information
function myVia(from, address)
{
  /*jshint validthis: true */
  if(typeof address != 'string'){
    return logger.warn('invalid see address',address);
  }
  var self = this;
  var parts = address.split(',');
  if(parts.length != 3 || parts[1].split('.').length != 4 || parseInt(parts[2] <= 0)){
    return;
  }
  if(parts[0] !== self.hashname){
    return;
  }
  if(utilities.isLocalIP(parts[1])){
    return; // ignore local IPs
  }
  // if it's a seed (trusted) or any, update our known public ipv4 IP/Port
  if(from.isSeed || !self.paths.pub4)
  {
    logger.debug('updating public ipv4',address);
    self.pathSet({
      type:'pub4',
      ip:parts[1],
      port:parseInt(parts[2])
    });
    self.address = address;
  }else{
    // TODO multiple public IPs?
  }
}

// seek the dht for this hashname
function seek(hn, callback)
{
  /*jshint validthis: true */
  var self = this;
  if(typeof hn == 'string'){
    hn = self.whois(hn);
  }

  var did = {};
  var doing = {};
  var queue = [];
  var closest = 255;
  
  // load up who we know closest
  self.nearby(hn.hashname).forEach(function(near){
    if(near === hn){
      return; // ignore the one we're (re)seeking
    }
    if(queue.indexOf(near.hashname) == -1){
      queue.push(near.hashname);
    }
  });
  logger.debug('seek starting with',queue);

  // always process potentials in order
  function sort()
  {
    queue = queue.sort(function(a,b){
      return utilities.dhash(hn.hashname,a) - utilities.dhash(hn.hashname,b);
    });
  }
  sort();

  // track when we finish
  function done(err)
  {
    // get all the hashnames we used/found and do final sort to return
    Object.keys(did).forEach(function(k){
      if(queue.indexOf(k) == -1){
        queue.push(k);
      }
    });
    Object.keys(doing).forEach(function(k){
      if(queue.indexOf(k) == -1){
        queue.push(k);
      }
    });
    sort();
    var cb;
    while((cb = hn.seeking.shift())){
      cb(err, queue.slice());
    }
  }

  // track callback(s);
  if(!hn.seeking){
    hn.seeking = [];
  }
  hn.seeking.push(callback);
  if(hn === self){
    return done(); // always a success heh
  } 
  if(hn.seeking.length > 1){
    return;
  }

  // main loop, multiples of these running at the same time
  function loop(onetime){
    if(!hn.seeking.length){
      return; // already returned
    }
    logger.debug('SEEK LOOP',queue);
    // if nothing left to do and nobody's doing anything, failed :(
    if(Object.keys(doing).length === 0 && queue.length === 0){
      return done('failed to find the hashname');
    }
    
    // get the next one to ask
    var mine = onetime || queue.shift();
    if(!mine){
      return; // another loop() is still running
    }

    // if we found it, yay! :)
    if(mine == hn.hashname){
      return done();
    }
    // skip dups
    if(did[mine] || doing[mine]){
      return onetime||loop();
    }
    var distance = utilities.dhash(hn.hashname, mine);
    if(distance > closest){
      return onetime||loop(); // don't "back up" further away
    }
    if(!self.seeds[mine]){
      closest = distance; // update distance if not talking to a seed
    }
    doing[mine] = true;
    var to = self.whois(mine);
    to.seek(hn.hashname, function(err, see){
      see.forEach(function(item){
        var sug = self.whois(item);
        if(sug === self){
          return; // happens
        }
        if(!sug){
          return logger.warn('bad see',item,to.hashname);
        }
        sug.via(to, item);
        queue.push(sug.hashname);
      });
      sort();
      did[mine] = true;
      delete doing[mine];
      if(!onetime){
        loop();
      }
    });
  }
  
  // start three of them
  loop();
  loop();
  loop();
  
  // also force query any locals
  self.locals.forEach(function(local){
    loop(local.hashname);
  });
}


// return array of nearby hashname objects
function nearby(hashname)
{
  /*jshint validthis: true */
  var self = this;
  var ret = {};
  
  // return up to 5 closest, in the same or higher (further) bucket
  var bucket = utilities.dhash(self.hashname, hashname);
  while(bucket <= 255 && Object.keys(ret).length < 5){
    if(self.buckets[bucket]){
      self.buckets[bucket].forEach(function(hn){
        if(!hn.alive){
          return; // only see ones we have a line with
        }
        ret[hn.hashname] = hn;
      });
    }
    bucket++;
  }

  // use any if still not full
  if(Object.keys(ret).length < 5){
    Object.keys(self.lines).forEach(function(line){
      if(Object.keys(ret).length >= 5){
        return;
      }
      if(!self.lines[line].alive){
        return;
      }
      ret[self.lines[line].hashname] = self.lines[line];
    });
  }
  var reta = [];
  Object.keys(ret).forEach(function(hn){
    reta.push(ret[hn]);
  });
  return reta;
}

exports.bridge = bridge;
exports.myVia = myVia;
exports.seek = seek;
exports.nearby = nearby;