const { Transactions, Identities, Crypto, Managers, Utils } = require('@arkecosystem/crypto');

const DEFAULT_RECENT_NONCES_MAX_COUNT = 10000;
const MAX_TRANSACTIONS_PER_TIMESTAMP = 100;
const API_BLOCK_FETCH_LIMIT = 50;
const DEFAULT_BLOCKS_LOOK_AHEAD_MAX_COUNT = 300;

class ArkChainCrypto {
  constructor({chainOptions}) {
    this.moduleAlias = chainOptions.moduleAlias;
    this.multisigPublicKey = chainOptions.multisigPublicKey;
    this.multisigAddress = Identities.Address.fromPublicKey(this.multisigPublicKey);
    this.passphrase = chainOptions.passphrase;
    this.memberAddress = Identities.Address.fromPassphrase(this.passphrase);
    this.memberPublicKey = Identities.PublicKey.fromPassphrase(this.passphrase);
    this.memberPrivateKey = Identities.PrivateKey.fromPassphrase(this.passphrase);
    this.recentNoncesMaxCount = chainOptions.recentNoncesMaxCount || DEFAULT_RECENT_NONCES_MAX_COUNT;
    this.blocksLookAheadMaxCount = chainOptions.blocksLookAheadMaxCount || DEFAULT_BLOCKS_LOOK_AHEAD_MAX_COUNT;
    this.nonceIndex = 0n;
  }

  async load(channel, lastProcessedHeight) {
    this.channel = channel;
    let account = await this.channel.invoke(`${this.moduleAlias}:getAccount`, {
      walletAddress: this.multisigAddress
    });
    this.initialAccountNonce = BigInt(account.nonce);
    this.multisigWalletKeys = account.attributes.multiSignature.publicKeys || [];
    this.memberMultisigIndex = this.multisigWalletKeys.indexOf(this.memberPublicKey);
    await this.reset(lastProcessedHeight);
  }

  async unload() {}

  async reset(lastProcessedHeight) {
    let lastProcessedBlock = await this.channel.invoke(`${this.moduleAlias}:getBlockAtHeight`, {
      height: lastProcessedHeight
    });

    let oldOutboundTxns = await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactions`, {
      walletAddress: this.multisigAddress,
      fromTimestamp: lastProcessedBlock.timestamp,
      limit: MAX_TRANSACTIONS_PER_TIMESTAMP,
      order: 'desc'
    });

    if (oldOutboundTxns.length) {
      let highestNonce = oldOutboundTxns.reduce((accumulator, txn) => {
        let txnNonce = BigInt(txn.nonce);
        if (txnNonce > accumulator) {
          return txnNonce;
        }
        return accumulator;
      }, 0n);
      this.nonceIndex = highestNonce + 1n;
    } else {
      this.nonceIndex = this.initialAccountNonce;
    }

    let newBlockMap = new Map();
    let currentHeight = lastProcessedBlock.height;
    while (newBlockMap.size < this.blocksLookAheadMaxCount) {
      let newBlocks = await this.channel.invoke(`${this.moduleAlias}:getBlocksBetweenHeights`, {
        fromHeight: currentHeight,
        limit: API_BLOCK_FETCH_LIMIT
      });
      if (!newBlocks.length) {
        break;
      }
      for (let block of newBlocks) {
        newBlockMap.set(block.height, block);
        currentHeight = block.height;
      }
    }

    this.recentNoncesMap = new Map();

    for (let block of newBlockMap.values()) {
      if (block.numberOfTransactions === 0) {
        continue;
      }
      let newOutboundTxns = await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactionsFromBlock`, {
        walletAddress: this.multisigAddress,
        blockId: block.id
      });
      for (let txn of newOutboundTxns) {
        this.recentNoncesMap.set(txn.id, BigInt(txn.nonce));
      }
    }
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
      id: transaction.id,
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

    let nonce = this._getNextNonce(transactionData);

    // Needs to be set to a height which supports version 2 transactions.
    Managers.configManager.setHeight(20000000);

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

    preparedTxn.data.senderAddress = this.multisigAddress;
    preparedTxn.data.recipientAddress = preparedTxn.data.recipientId;
    preparedTxn.data.amount = preparedTxn.data.amount.toString();
    preparedTxn.data.fee = preparedTxn.data.fee.toString();
    preparedTxn.data.message = preparedTxn.data.vendorField || '';
    preparedTxn.data.nonce = preparedTxn.data.nonce.toString();
    preparedTxn.data.signatures = [];

    delete preparedTxn.data.recipientId;
    delete preparedTxn.data.vendorField;

    return {transaction: preparedTxn.data, signature: multisigTxnSignature};
  }

  _getNextNonce(transactionData) {
    let tradeId = transactionData.id;
    let existingNonce = this.recentNoncesMap.get(tradeId);

    if (existingNonce == null) {
      this.recentNoncesMap.set(tradeId, this.nonceIndex);
      while (this.recentNoncesMap.size > this.recentNoncesMaxCount) {
        let nextKey = this.recentNoncesMap.keys().next().value;
        this.recentNoncesMap.delete(nextKey);
      }
    } else {
      this.nonceIndex = existingNonce;
    }

    return this.nonceIndex++;
  }
}

async function wait(duration) {
  return new Promise((resolve) => {
    setTimeout(resolve, duration);
  });
}

module.exports = ArkChainCrypto;
