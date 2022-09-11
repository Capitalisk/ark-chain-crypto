const assert = require('assert');
const ArkChainCrypto = require('../index');
const Channel = require('./utils/channel');

describe('DEX (ChainCrypto) API tests', async () => {
  let options;
  let chainCrypto;
  let preparedTxn;
  let signaturePacket;
  let store;
  let channel;

  beforeEach(async () => {
    store = {};
    options = {
      chainOptions: {
        multisigPublicKey: '0398db7e710602fffe50f137d536735c7fc1bcfa79cefd659cb7b8d118bf5bbbf0',
        passphrase: 'tell sun crazy time creek carbon cloud various turtle leisure cactus melody',
        keyIndexDirPath: './test/data/',
        rpcURL: 'ws://216.128.135.183:8080/ws'
      }
    };
    channel = new Channel();
    chainCrypto = new ArkChainCrypto(options);
    await chainCrypto.load(channel, 100);
  });

  afterEach(async () => {
    await chainCrypto.unload();
  });

  describe('prepareTransaction', async () => {

    it('should prepare and sign transaction and return transaction and signature objects with all required properties', async () => {
      let { transaction, signature } = await chainCrypto.prepareTransaction({
        recipientAddress: 'DHdJbhdrgKoCJczmfGrPKjjcz3yvTDRinH',
        amount: '10000000000',
        fee: '10000000',
        timestamp: 1609544665,
        message: ''
      });

      assert.notEqual(transaction, null);
      assert.equal(typeof transaction.id, 'string');

      // The signatures property should be an empty array.
      // The DEX module will use the signatures array to store signature packets
      // from the current DEX node and also other DEX nodes.
      assert.equal(Array.isArray(transaction.signatures), true);
      assert.equal(transaction.signatures.length, 0);

      // The signature should be an object with a signerAddress property which holds
      // the wallet address of the signer.
      // Apart from that, the schema of the signature object is flexible; whatever
      // is supported by the verifyTransactionSignature method.
      assert.notEqual(signature, null);
      assert.equal(typeof signature.signerAddress, 'string');
    });

  });

  describe('verifyTransactionSignature', async () => {

    beforeEach(async () => {
      let { transaction, signature } = await chainCrypto.prepareTransaction({
        recipientAddress: 'DHdJbhdrgKoCJczmfGrPKjjcz3yvTDRinH',
        amount: '10000000000',
        fee: '10000000',
        timestamp: 1609544665,
        message: ''
      });
      preparedTxn = transaction;
      signaturePacket = signature;
    });

    it('should return true if the signature belongs to the correct account and is valid', async () => {
      let isValid = await chainCrypto.verifyTransactionSignature(preparedTxn, signaturePacket);
      assert.equal(isValid, true);
    });

    it('should return false if the signature belongs to the correct account but is not valid', async () => {
      signaturePacket.signature = signaturePacket.signature.replace(/a/g, 'b');
      let isValid = await chainCrypto.verifyTransactionSignature(preparedTxn, signaturePacket);
      assert.equal(isValid, false);
    });

    it('should return false if the signature is valid but does not belong to the correct account', async () => {
      signaturePacket.signerAddress = 'DTY1sPZrWDynB5zDYrhuv1oZ5SHNfc7Bnm';
      let isValid = await chainCrypto.verifyTransactionSignature(preparedTxn, signaturePacket);
      assert.equal(isValid, false);
    });

  });

});
