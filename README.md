Node.js
=======

# Overview

[![telehash](https://nodei.co/npm/telehash.png)](https://nodei.co/npm/telehash/)
	
This module presents a simple high-level API for using [telehash](https://github.com/telehash/telehash.org/blob/master/protocol.md). It is still in development and not stable yet, but issues and pull requests are welcome.

# Seeds

Telehash apps always need one or more seeds to bootstrap from, the default development testing ones are in [seeds.json](https://github.com/telehash/thjs/blob/master/seeds.json).  You can run your own seed via `npm start` or manually via `node seed/seed.js`.

Take the output JSON, put it in an array and in your own seeds.json file, then load it with `.addSeeds("./seeds.json")`.

# "Field Test" Utility

There is a field test command line utility included to explore the DHT and connect to other hashnames, just run `node fieldtest/tft.js`.

# Library Interface

In all of these examples, the `th` object is created via `var th = require("telehash");`.

## Identity / Keypair Generation

```js
th.genkey(function(err, key){
  if(err) return console.log("key generation failed",err);
  // key contains a .public and .private of the PEM-encoded RSA-2048 public and private values
});
```

## Hashname Initialization / Startup

Needs a key object containing a .public and .private (generated above) to create our own hashname:

```js
var app = th.hashname(key);
console.log("hashname created",app.hashname);
app.addSeeds("./seeds.json"); // optional, uses bundled seeds otherwise
app.online(function(err){
  if(err) return console.log("hashname failed to come online");
});
```

The `.online` takes a callback that is fired when the hashname is able to connect to any seeds and become part of the DHT or fails to do so.

## Listening for incoming channels

```js
app.listen("chat", function(end, arg, chan, callback){
  // end is `true` when the incoming channel is ended
  // arg.js contains the incoming json, arg.body any binary body
  // chan is the channel interface
  // callback() must be called when done to continue
});
```

## Starting a new channel

```js
app.whois("hashname").start("type", argOut, function(end, argIn, chan, callback){
  // same as listening, except argOut contains an optional .js and .body to be sent in the initial channel request
});
```

Browser
========

To package the library run

```js
npm run build
```

To try it out in any browser, put these files on any web server and load fieldtest/index.html, or even from your local filesystem via file:///path-to-thjs/fieldtest/index.html.

The crypto that powers this is only possible thanks to the incredible work done by the team behind [Forge](https://github.com/digitalbazaar/forge) and [Tom Wu](http://www-cs-students.stanford.edu/~tjw/).
