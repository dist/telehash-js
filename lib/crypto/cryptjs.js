// this loads the pure-javascript crypto bindings used by thjs

exports.load = function(){
  // TODO get these ported to forge or packaged better or something, so brute force!
  require('./includes/browser/jsbn');
  require('./includes/browser/jsbn2');
  require('./includes/browser/ec');
  require('./includes/browser/sec');
  require('./includes/browser/prng4');
  require('./includes/browser/rng');

  global.getSECCurveByName = getSECCurveByName;
  global.BigInteger = BigInteger;
  global.SecureRandom = SecureRandom;
  global.ECPointFp = ECPointFp;
  return require("./thforge").forge(forge);
}


