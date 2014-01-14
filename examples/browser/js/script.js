'use strict';
/*jshint browser:true*/
/*global telehash:true,seeds:true,$:true,thweb:true,forge:true,io:true*/

function getId(callback)
{
  if(localStorage.nick)
  {
    var ret = {
      nick:localStorage.nick,
      public:localStorage.pubkey,
      private:localStorage.prikey
    };
    console.log('returning key',ret);
    ret.seeds = seeds;
    return callback(ret);
  }else{
    // generate/save one nicely
    window.alert('generating private local id, this only happens once and should be less than 30 seconds');
    telehash.genkey(function(err, keys){
      if(err){
        return window.alert('error: '+err);
      }
      localStorage.pubkey = keys.public;
      localStorage.prikey = keys.private;
      localStorage.nick = window.prompt('enter a nickname');
      getId(callback);
    });
  }
}

$(document).ready(function() {
  console.log('READY');
  getId(function(id){
    var sockets = {};
    console.log('STARTING');
      var me = telehash.hashname(id, function(path, msg, to) {
        if(path.type == 'webrtc' && me.paths.webrtc)
        {
          console.log('sending webrtc', to.hashname, msg.length());
          if(!sockets[path.id]){
            sockets[path.id] = thweb.rtc(me,{to:to.hashname,id:path.id});
          }
          sockets[path.id].send(msg.bytes());
        }else if(path.type == 'http')
        {
          console.log('sending http', to.hashname, msg.length());
          if(!sockets[path.http]){
            sockets[path.http] = io.connect(path.http);
            sockets[path.http].on('packet', function(packet){
              me.receive(forge.util.decode64(packet.data), path);
            });
          }
          sockets[path.http].emit('packet', {
            data: forge.util.encode64(msg.bytes())
          });
        }else{
          console.log('dropping ',path.type);
        }
      });

      thweb.rtcAdd(me,sockets); // enable webrtc if possible
      console.log('switch created',me);
      id.seeds.forEach(me.addSeed, me);
      me.online(function(err){
        if(err){
          $('#error').html(err);
          $('#error').show();
          return;
        }

        function log(a,b,c,d,e,f){
          var message = [a,b,c,d,e,f].join(' ');
          $('#systemMessageTemplate').tmpl({
            message: message
          }).appendTo('#messages');
          $('#messages').scrollTop($('#messages').prop('scrollHeight') - $('#messages').height());
        }

        log('online',me.hashname,err);

        function chat(nick, message){
          $('#chatMessageTemplate').tmpl({
            sender:nick,
            message: message
          }).appendTo('#messages');
          $('#messages').scrollTop($('#messages').prop('scrollHeight') - $('#messages').height());
        }

        function join(user) {
          $('#userTemplate').tmpl({user: user}).appendTo('#users');
          log(user+' joined');
        }

        var nicks = {};

        function messageInit(err, arg, chan, cb)
        {
          if(err){
            return log('message handshake err',err);
          }
          chan.nick = (arg.js.nick) ? arg.js.nick : chan.hashname.substr(0,6);
          nicks[chan.nick] = chan;
          join(chan.nick);
          log('m['+chan.nick+'] connected');
          chan.callback = function(err, arg, chan, cbMessage){
            if(arg && arg.js.message){
              chat(chan.nick,arg.js.message);
            }
            if(err){
              $('#user-' + chan.nick).remove();
              log('m['+chan.nick+'] disconnected',err);
              delete nicks[chan.nick];
            }
            cbMessage();
          };
          cb();
        }

        // configure a channel for group mode
        function groupInit(arg, chan)
        {
          chan.nick = (arg.js.nick) ? arg.js.nick : chan.hashname.substr(0,6);
          chan.nick = chan.group.id+':'+chan.nick;
          join(chan.nick);
          log('g['+chan.nick+'] joined');
          chan.callback = function(err, arg, chan, cbMessage){
            if(arg && arg.js.message){
              chat(chan.nick,arg.js.message);
            }
            if(err)
            {
              $('#user-' + chan.nick).remove();
              log('g['+chan.nick+'] left',err);
              delete chan.group.members[chan.hashname];
            }
            cbMessage();
          };
        }
        
        var groups = {
          ids:{},
          get:function(id){
            if(groups.ids[id]){
              return groups.ids[id];
            }
            var group = groups.ids[id] = {id:id,members:{}};

            group.add = function(chan){
              chan.group = group;
              group.members[chan.hashname] = chan;
            };

            return group;
          }
        };

        var cmds = {};

        cmds.help = cmds['?'] = function(arg){
          log('"whoami"','your info');
          log('"seek hashname"','look for that hashname in the DHT');
          log('"ping hashname"','try to connect to and get response from that hashname');
          log('"h hashname"','show info on hashname');
          log('"a|all"','show all connected hashnames');
          log('"add hashname"','add a hashname to send messages to');
          log('"m|message nick"','send a message to the nickname');
          log('"w|who"','which nicknames are attached');
          log('"join group"','create a group that others can join');
          log('"join group hashname"','join a group that exists via that hashname');
          log('"gw|gwho group"','see who\'s in the group');
          log('"gm group"','send a message to the group');
        };

        cmds.whoami = function(){
          log('I am',id.nick,me.hashname,JSON.stringify(me.paths));
        };

        cmds['42'] = function(){
          log('I hash, therefore I am.');
        };

        cmds.add = function(arg){
          var host = me.whois(arg[0]);
          if(!host){
            return log('invalid hashname',arg[0]);
          }
          log('adding',host.hashname);
          host.start('message', {
            js:{
              nick:id.nick
            }
          }, messageInit);
        };

        cmds.h = function(arg){
          var host = me.whois(arg[0]);
          if(!host){
            return log('invalid hashname',arg[0]);
          }
          if(host.relay){
            log('relay',JSON.stringify(host.relay));
          }
          host.paths.forEach(function(path){
            log('path',JSON.stringify(path));
          });
          Object.keys(host.chans).forEach(function(c){
            log('chan',host.chans[c].type,host.chans[c].id);
          });
        };

        cmds.message = cmds.m = function(arg){
          if(!nicks[arg[0]]){
            return log('unknown recipient',arg[0]);
          }
          var msg = arg.join(' ');
          chat(id.nick,msg);
          nicks[arg.shift()].send({
            js:{message:msg
            }
          });
        };

        cmds.who = cmds.w = function()
        {
          Object.keys(nicks).forEach(function(nick){
            log(nick,nicks[nick].hashname);
          });
        };

        cmds.all = cmds.a = function()
        {
          Object.keys(me.lines).forEach(function(line){
            var hn = me.lines[line];
            log(hn.address,Object.keys(hn.chans).length);
          });
        };

        cmds.gw = cmds.gwho = function(arg){
          var group = groups.get(arg.shift());
          Object.keys(group.members).forEach(function(member){
            log(group.members[member].nick,group.members[member].hashname);
          });
        };

        cmds.g = function(arg){
          var group = groups.get(arg.shift());
          var msg = arg.join(' ');
          chat(group.id+':'+id.nick,msg);
          Object.keys(group.members).forEach(function(member){
            group.members[member].send({js:{message:msg}});
          });
        };

        cmds.join = function(arg)
        {
          var group = groups.get(arg[0]);
          if(!arg[1]){
            return join(group.id+':'+id.nick);
          }
          
          var host = me.whois(arg[1]);
          if(!host){
            return log('invalid group hashname',arg[1]);
          }
          log('g['+group.id+'] fetching members');
          host.start('members', {
            js:{
              group:group.id
            }
          }, function(err, arg, chan, cb)
          {
            if(err && err !== true){
              return log('group',group.id,'error fetching members',err);
            }
            if(Array.isArray(arg.js.members)){
              arg.js.members.forEach(function(member){
                if(group.members[member]){
                  return;
                }
                if(member == me.hashname){
                  return;
                }
                var hn = me.whois(member);
                if(!hn){
                  return log('g['+group.id+'] invalid member',member);
                }
                hn.start('group', {
                  js:{
                    nick:id.nick,
                    group:group.id
                  }
                }, function(err, arg, chan, cb){
                  if(err){
                    return log('message handshake err',err);
                  }
                  group.add(chan);
                  groupInit(arg, chan);
                  cb();
                });
              });
            }
            cb();
          });
        };

        cmds.seek = function(arg)
        {
          var hn = me.whois(arg[0]);
          if(!hn){
            return log('invalid hashname',arg[0]);
          }
          me.seek(hn, function(err, seen){
            if(err){
              return log('seek failed',hn.hashname,err);
            }
            log('seek',hn.hashname,JSON.stringify(hn.vias));
            log('seen',seen&&seen.join(' '));
          });
        };

        cmds.ping = function(arg)
        {
          var hn = me.whois(arg[0]);
          if(!hn){
            return log('invalid hashname',arg[0]);
          }
          var start = Date.now();
          hn.seek(me.hashname,function(err){
            if(err && err !== true){
              return log('ping failed',hn.hashname,err);
            }
            log('pong',hn.address,Date.now()-start);
          });
        };

        cmds.bulk = function(arg)
        {
          var hn = me.whois(arg.shift());
          if(!hn){
            return log('invalid hashname');
          }
          hn.start('bulk',{
            js:{
              tft:true
            }
          },function(err,packet,chan,cb){
            cb();
            if(err){
              return log('bulk failed',hn.hashname,err);
            }
            chan.wrap('bulk');
            chan.bulk(arg.join(' '), function(err){
              log('bulked',err);
            });
          });
        };

        cmds.rtc = function(arg)
        {
          var hn = me.whois(arg.shift());
          if(!hn){
            return log('invalid hashname');
          }
          // TODO demo generic webrtc call signalling
        };
        
        // actual startup
        join(id.nick);

        me.listen('webrtc', function(err, arg, chan, cb){
          cb();
          chan.send({
            js:{
              open:true
            }
          });
            // TODO demo generic webrtc answer signalling
        });

        me.listen('message', function(err, arg, chan, cb){
          messageInit(false, arg, chan, cb);
          chan.send({
            js:{
              nick:id.nick
            }
          });
        });

        me.listen('group', function(err, arg, chan, cb){
          if(!arg.js.group){
            return log('missing group error from',chan.hashname);
          }
          groups.get(arg.js.group).add(chan);
          groupInit(arg, chan);
          chan.send({js:{nick:id.nick}});
          cb();
        });

        me.listen('members', function(err, arg, chan, cb){
          // send members in chunks
          cb();
          var group = groups.get(arg.js.group);
          var mlist = Object.keys(group.members);
          mlist.push(me.hashname); // always include yourself
          while(mlist.length > 0)
          {
            var chunk = mlist.slice(0, 10);
            mlist = mlist.slice(10);
            chan.send({js:{members:chunk}});
            if(mlist.length === 0){
              chan.end();
            }
          }
        });

        me.listen('bulk', function(err, arg, chan, cb){
          log('bulk started from',chan.hashname);
          chan.wrap('bulk');
          chan.onBulk = function(err, data){
            if(err){
              return log('bulk error',err);
            }
            log('bulk received:',data);
          };
          chan.send({
            js:{
              tft:true
            }
          });
          cb();
        });

        me.socket('/', function(socket){
          log('TS new',socket.id,socket.hashname);
          socket.onmessage = function(msg){
            log('TS',socket.id,msg.data);
          };
          socket.onclose = function(){
            log('TS close',socket.id);
          };
        });

        $('#message-input').focus();

        $('#message-form').submit(function(ev) {
            ev.preventDefault();
            var message = $('#message-input').val();
            $('#message-input').val('');
            var parts = message.split(' ');
            var cmd = parts.shift();
            if(cmds[cmd]){
              cmds[cmd](parts);
            }
            else{
              log('I don\'t know how to '+cmd);
            }
        });
      });
  });
});