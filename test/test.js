var mnemoauth = require('../index.js');
var expect = require('chai').expect;

var FIXTURES = {
  mnemonic: 'uniform toward toe purpose roof river brave disagree nation pull need catalog early adjust',
  base58: 'xprv9s21ZrQH143K2rxUBAi88HqGfbutG1B4T7W2LB4KGiwtfPF7T9UaGwxTsBWSqW2eAA5aTX8BDBvMKz4tSL4wxzg6JmH9HDZqHjCpbKWrLQL',
  publicKey: '2A9sisBaaCZHJiAZnWE59w4tEgPiXAG6mjJfm8gb8NHMw',
  messageHash: 'FebCUHJuraNkNpA9thp6wGx5h1ay5Q9CThJ5EcfCC1Fc',
  signatures: {
    signup: 'AN1rKvtUQCVknYm1bpnQSJEeiKhi3mPAhJUswxSDhnXmDe2imhTXh86dLBJtUbPmRMFK8wPsKC7h4ryKK8LDmcEmkozWwoGm4',
    testRequest: 'AN1rKvt1RDeqRDSmvim5fACG2Qkr3U3ZTj8d5cyEvC2DQeXqEgiKCvmq79dtPNEKyydH5ZSgn7smpfP4ECCQsdXQtnm5jaZVs',
  }
}

describe('generateMnemonic', function() {
  it('should generate a 14-word mnemonic', function() {
    var mnemonic = mnemoauth.generateMnemonic();
    expect(mnemonic.split(' ')).to.have.length(14)
  });
});

describe('HDNodeFromMnemonic', function() {
  it('should return HDNode from mnemonic', function() {
    var hd = mnemoauth.HDNodeFromMnemonic(FIXTURES.mnemonic);
    expect(hd.toBase58()).to.equal(FIXTURES.base58);
  });
});

describe('Signing', function() {
  var hd;
  before(function() {
    hd = mnemoauth.HDNodeFromMnemonic(FIXTURES.mnemonic)
  });

  describe('generateSignupRequest', function() {
    it('should generate a valid signup request', function() {
      var request = mnemoauth.generateSignupRequest(hd);
      expect(request.publicKey).to.equal(FIXTURES.publicKey);
      expect(request.messageHash).to.equal(FIXTURES.messageHash);
      expect(request.signature).to.equal(FIXTURES.signatures.signup);
    });
  });

  describe('signRequest', function() {
    it('should return a request signature', function() {
      var headers = mnemoauth.signRequest(hd, 'POST', '/test', {ok: true})
      expect(headers['x-public-key']).to.equal(FIXTURES.publicKey);
      expect(headers['x-signature']).to.equal(FIXTURES.signatures.testRequest);
    });
  });
});

