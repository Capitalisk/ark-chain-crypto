const crypto = require('crypto');
const { Transactions, Identities, Crypto, Managers, Utils } = require('capitalisk-ark-crypto');

const DEFAULT_MAX_TRANSACTIONS_PER_TIMESTAMP = 300;

class ArkChainCrypto {
  constructor({chainOptions, logger}) {
    this.moduleAlias = chainOptions.moduleAlias;
    this.multisigPublicKey = chainOptions.multisigPublicKey;
    this.multisigAddress = Identities.Address.fromPublicKey(this.multisigPublicKey);
    this.passphrase = chainOptions.passphrase;
    this.memberAddress = Identities.Address.fromPassphrase(this.passphrase);
    this.memberPublicKey = Identities.PublicKey.fromPassphrase(this.passphrase);
    this.memberPrivateKey = Identities.PrivateKey.fromPassphrase(this.passphrase);
    this.maxTransactionsPerTimestamp = chainOptions.maxTransactionsPerTimestamp || DEFAULT_MAX_TRANSACTIONS_PER_TIMESTAMP;
    this.nonceIndex = 0n;
    this.logger = logger;
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
    // Needs to be set to a height which supports version 2 transactions.
    Managers.configManager.setHeight(20000000);

    let lastProcessedBlock = await this.channel.invoke(`${this.moduleAlias}:getBlockAtHeight`, {
      height: lastProcessedHeight
    });

    let highestNonceTransaction = null;
    let currentTimestamp = lastProcessedBlock.timestamp;

    while (true) {
      let oldOutboundTxns = await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactions`, {
        walletAddress: this.multisigAddress,
        fromTimestamp: currentTimestamp,
        limit: this.maxTransactionsPerTimestamp,
        order: 'desc'
      });
      if (!oldOutboundTxns.length) {
        break;
      }
      oldOutboundTxns.sort((a, b) => Number(BigInt(b.nonce) - BigInt(a.nonce)));
      for (let txn of oldOutboundTxns) {
        let currentBlock = await this.channel.invoke(`${this.moduleAlias}:getBlock`, {
          blockId: txn.blockId
        });
        if (currentBlock.height <= lastProcessedHeight) {
          highestNonceTransaction = txn;
          break;
        }
      }
      if (highestNonceTransaction) {
        break;
      }

      let nextTimestamp = oldOutboundTxns[oldOutboundTxns.length - 1].timestamp;
      if (nextTimestamp < currentTimestamp) {
        currentTimestamp = nextTimestamp;
      } else {
        this.logger.error(
          `Failed to fetch some transactions at timestamp ${
            currentTimestamp
          } while resetting the Ark ChainCrypto DEX plugin - Transaction nonces may be incorrect`
        );
        currentTimestamp--;
      }
      if (currentTimestamp < 0) {
        break;
      }
    }

    if (highestNonceTransaction) {
      this.nonceIndex = BigInt(highestNonceTransaction.nonce) + 1n;
    } else {
      this.nonceIndex = this.initialAccountNonce;
    }
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

    let nonce = this.nonceIndex++;

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
    preparedTxn.data.id = this.computeDEXTransactionId(
      preparedTxn.data.senderAddress,
      preparedTxn.data.nonce
    );
    preparedTxn.data.signatures = [];

    delete preparedTxn.data.recipientId;
    delete preparedTxn.data.vendorField;

    return {transaction: preparedTxn.data, signature: multisigTxnSignature};
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
