const crypto = require('crypto');
const { Transactions, Identities, Crypto, Managers, Utils } = require('capitalisk-ark-crypto');


class ArkChainCrypto {
  constructor({chainOptions, logger}) {
    Managers.configManager.setFromPreset(chainOptions.env || 'devnet');
    // Needs to be set to a height which supports version 2 transactions.
    Managers.configManager.setHeight(20000000);

    this.moduleAlias = chainOptions.moduleAlias;
    this.multisigPublicKey = chainOptions.multisigPublicKey;
    this.multisigAddress = Identities.Address.fromPublicKey(this.multisigPublicKey);
    this.passphrase = chainOptions.passphrase;
    this.memberAddress = Identities.Address.fromPassphrase(this.passphrase);
    this.memberPublicKey = Identities.PublicKey.fromPassphrase(this.passphrase);
    this.memberPrivateKey = Identities.PrivateKey.fromPassphrase(this.passphrase);
    this.logger = logger;
  }

  async load(channel, lastProcessedHeight) {
    this.channel = channel;
    let account = await this.getAccount();
    this.initialAccountNonce = BigInt(account.nonce);
    this.multisigWalletKeys = account.attributes.multiSignature.publicKeys || [];
    this.memberMultisigIndex = this.multisigWalletKeys.indexOf(this.memberPublicKey);
    this.lastBlockTransactionId = null;
    this.lastBlockTransactionNonce = null;

    await this.reset(lastProcessedHeight);
  }

  async unload() {}

  async reset(lastProcessedHeight) {
    let lastProcessedBlock = await this.channel.invoke(`${this.moduleAlias}:getBlockAtHeight`, {
      height: lastProcessedHeight
    });

    this.nonceIndex = this.getLastOutboundTransactionNonce(lastProcessedBlock.timestamp);

    this.logger.debug(
      `Ark ChainCrypto nonce was reset to ${this.nonceIndex} at height ${lastProcessedHeight}`
    );
  }

  // This method checks that:
  // 1. The signerAddress corresponds to the publicKey.
  // 2. The publicKey corresponds to the signature.
  async verifyTransactionSignature(transaction, signaturePacket) {
    let { signature: signatureToVerify, publicKey, signerAddress } = signaturePacket;
    let expectedAddress = Identities.Address.fromPublicKey(publicKey);

    if (signerAddress !== expectedAddress) {
      return false;
    }

    let txn = {
      version: transaction.version,
      network: transaction.network,
      id: transaction.originalId,
      type: transaction.type,
      typeGroup: transaction.typeGroup,
      senderPublicKey: transaction.senderPublicKey,
      recipientId: transaction.recipientAddress,
      amount: new Utils.BigNumber(transaction.amount),
      fee: new Utils.BigNumber(transaction.fee),
      expiration: transaction.expiration,
      nonce: new Utils.BigNumber(transaction.nonce),
      vendorField: transaction.message,
      signatures: []
    };

    let txnHash = Transactions.Utils.toHash(txn, {
      excludeSignature: true,
      excludeSecondSignature: true,
      excludeMultiSignature: true,
    });

    return Crypto.Hash.verifySchnorr(txnHash, (signatureToVerify || '').slice(2, 130), publicKey);
  }

  async prepareTransaction(transactionData) {
    if (!Identities.Address.validate(transactionData.recipientAddress)) {
      throw new Error(
        'Failed to prepare the transaction because the recipientAddress was invalid'
      );
    }
    let nonce = ++this.nonceIndex;
    let transactionId = this.computeDEXTransactionId(
      this.multisigAddress,
      nonce.toString()
    );

    if (this.lastTimestamp !== transactionData.timestamp) {
      // Only attempt to correct the nonceIndex at most once per timestamp
      // for the first transaction in the block.
      this.lastTimestamp = transactionData.timestamp;

      // If a transaction id has already been processed before (e.g. because of
      // an error during block processing), roll back the nonce to its previous value.
      if (transactionId === this.lastBlockTransactionId) {
        nonce = this.lastBlockTransactionNonce;
        this.nonceIndex = nonce;
      } else {
        this.lastBlockTransactionNonce = nonce;
      }
      this.lastBlockTransactionId = transactionId;

      // If the current nonce is lower than expected, exit and restart the module.
      // This will allow the module to resync from an earlier safe height and
      // will ensure that no invalid pending transactions will be in the queue.
      let lastOutboundTransactionNonce = await this.getLastOutboundTransactionNonce(transactionData.timestamp);
      let expectedMinNextNonce = lastOutboundTransactionNonce + 1n;
      if (expectedMinNextNonce > this.nonceIndex) {
        this.logger.error(
          `Ark ChainCrypto nonce of ${
            this.nonceIndex
          } was less than the minimum expected value of ${
            expectedMinNextNonce
          }`
        );
        process.exit(1);
      }
    }

    let transferBuilder = Transactions.BuilderFactory.transfer();

    let preparedTxn = transferBuilder
      .version(2)
      .nonce(nonce)
      .amount(transactionData.amount)
      .fee(transactionData.fee)
      .senderPublicKey(this.multisigPublicKey)
      .recipientId(transactionData.recipientAddress)
      .timestamp(transactionData.timestamp)
      .vendorField(transactionData.message || '')
      .build();

    let signature = Transactions.Signer.multiSign(preparedTxn.data, {
      publicKey: this.memberPublicKey,
      privateKey: this.memberPrivateKey,
    }, this.memberMultisigIndex);

    // The signature needs to be an object with a signerAddress property, the other
    // properties are flexible and depend on the requirements of the underlying blockchain.
    let multisigTxnSignature = {
      signerAddress: this.memberAddress,
      publicKey: this.memberPublicKey,
      signature
    };

    preparedTxn.data.originalId = preparedTxn.data.id;
    preparedTxn.data.senderAddress = this.multisigAddress;
    preparedTxn.data.recipientAddress = preparedTxn.data.recipientId;
    preparedTxn.data.amount = preparedTxn.data.amount.toString();
    preparedTxn.data.fee = preparedTxn.data.fee.toString();
    preparedTxn.data.message = preparedTxn.data.vendorField || '';
    preparedTxn.data.nonce = preparedTxn.data.nonce.toString();
    preparedTxn.data.id = transactionId;
    preparedTxn.data.signatures = [];

    delete preparedTxn.data.recipientId;
    delete preparedTxn.data.vendorField;

    return {transaction: preparedTxn.data, signature: multisigTxnSignature};
  }

  async getAccount() {
    return this.channel.invoke(`${this.moduleAlias}:getAccount`, {
      walletAddress: this.multisigAddress
    });
  }

  async getLastOutboundTransaction(fromTimestamp) {
    return (
      await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactions`, {
        walletAddress: this.multisigAddress,
        fromTimestamp,
        limit: 1,
        order: 'desc'
      })
    )[0];
  }

  async getLastOutboundTransactionNonce(fromTimestamp) {
    let lastOutboundTransaction = await this.getLastOutboundTransaction(fromTimestamp);
    return lastOutboundTransaction ? BigInt(lastOutboundTransaction.nonce) : this.initialAccountNonce;
  }

  computeDEXTransactionId(senderAddress, nonce) {
    return crypto.createHash('sha256').update(`${senderAddress}-${nonce}`).digest('hex');
  }
}

async function wait(duration) {
  return new Promise((resolve) => {
    setTimeout(resolve, duration);
  });
}

module.exports = ArkChainCrypto;
