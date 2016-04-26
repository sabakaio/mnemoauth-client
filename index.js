var bitcoin = require('bitcoinjs-lib');
var bip39 = require('bip39');
var bs58 = require('bs58');

function generateMnemonic() {
  return bip39.generateMnemonic(144);
}

function HDNodeFromMnemonic(mnemonic) {
  var seed = bip39.mnemonicToSeedHex(mnemonic);
  var hd = bitcoin.HDNode.fromSeedHex(seed);
  return hd;
}

function generateSignupRequest(hd) {
  var authKey = deriveAuthKey(hd);
  var publicKey = authKey.getPublicKeyBuffer();
  var messageHash = bitcoin.crypto.hash256(publicKey);
  var signature = authKey.sign(messageHash).toDER();
  return {
    publicKey: bs58.encode(publicKey),
    messageHash: bs58.encode(messageHash),
    signature: bs58.encode(signature),
  }
}

function signRequest(hd, method, url, data) {
  var request = [method, url, JSON.stringify(data)].join("|");
  var authKey = deriveAuthKey(hd);
  var publicKey = authKey.getPublicKeyBuffer();
  var messageHash = bitcoin.crypto.hash256(request);
  var signature = authKey.sign(messageHash).toDER();
  return {
    'x-public-key': bs58.encode(publicKey),
    'x-signature': bs58.encode(signature),
  }
}

function deriveAuthKey(hd) {
  return hd.derive("m/1/1");
}

module.exports = {
  generateMnemonic: generateMnemonic,
  HDNodeFromMnemonic: HDNodeFromMnemonic,
  generateSignupRequest: generateSignupRequest,
  signRequest: signRequest,
}
