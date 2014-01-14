'use strict';

var utilities = require('./utilities');

// drop hn into it's appropriate bucket
function bucketize(self, hn)
{
  if(!hn.bucket){
	hn.bucket = utilities.dhash(self.hashname, hn.hashname);
  }

  if(!self.buckets[hn.bucket]){
	self.buckets[hn.bucket] = [];
  }
  
  if(self.buckets[hn.bucket].indexOf(hn) == -1){
	self.buckets[hn.bucket].push(hn);
  }
}
exports.bucketize = bucketize;