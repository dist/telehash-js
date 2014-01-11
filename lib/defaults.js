'use strict';
var defaults = {};
defaults.chan_timeout = 10000; // how long before for ending durable channels w/ no acks
defaults.seek_timeout = 3000; // shorter tolerance for seeks, is far more lossy
defaults.chan_autoack = 1000; // is how often we auto ack if the app isn't generating responses in a durable channel
defaults.chan_resend = 2000; // resend the last packet after this long if it wasn't acked in a durable channel
defaults.chan_outbuf = 100; // max size of outgoing buffer before applying backpressure
defaults.chan_inbuf = 50; // how many incoming packets to cache during processing/misses
defaults.mesh_timer = 25*1000; // how often the DHT mesh maintenance runs, twice a minute, must be <1min to maintain NAT mappings
defaults.nat_timeout = 60*1000; // nat timeout for inactivity
defaults.idle_timeout = 5*60*1000; // overall inactivity timeout
defaults.mesh_max = 250; // maximum number of nodes to maintain (minimum one packet per mesh timer)

module.exports=defaults;