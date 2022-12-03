const crypto = require('crypto');
const { Transactions, Identities, Crypto, Managers, Utils } = require('capitalisk-ark-crypto');
const DEFAULT_MAX_TRANSACTIONS_PER_TIMESTAMP = 300;
const FETCH_RETRY_DELAY = 5000;
// Approximately 24 hours since each iteration looks ahead 300 blocks and each
// block is 8 seconds apart.
const DEFAULT_MAX_CALIBRATION_LOOK_AHEAD = 36;

class ArkChainCrypto {
  constructor({chainOptions, logger}) {
    Managers.configManager.setFromPreset(chainOptions.env || 'devnet');
    // Needs to be set to a height which supports version 2 transactions.
    Managers.configManager.setHeight(20000000);

    this.moduleAlias = chainOptions.moduleAlias;
    this.multisigPublicKey = chainOptions.multisigPublicKey;
    this.multisigAddress = Identities.Address.fromPublicKey(this.multisigPublicKey);
    this.passphrase = chainOptions.passphrase;
    this.maxCalibrationLookAhead = chainOptions.maxCalibrationLookAhead || DEFAULT_MAX_CALIBRATION_LOOK_AHEAD;
    this.maxTransactionsPerTimestamp = chainOptions.maxTransactionsPerTimestamp || DEFAULT_MAX_TRANSACTIONS_PER_TIMESTAMP;
    this.memberAddress = Identities.Address.fromPassphrase(this.passphrase);
    this.memberPublicKey = Identities.PublicKey.fromPassphrase(this.passphrase);
    this.memberPrivateKey = Identities.PrivateKey.fromPassphrase(this.passphrase);
    this.logger = logger;
  }

  async load(channel, lastProcessedHeight) {
    this.channel = channel;
    let account = await this.getAccount();
    this.multisigWalletKeys = account.attributes.multiSignature.publicKeys || [];
    this.memberMultisigIndex = this.multisigWalletKeys.indexOf(this.memberPublicKey);

    await this.reset(lastProcessedHeight);
  }

  async unload() {}

  async reset(lastProcessedHeight) {
    this.nonceIndex = null;
    this.isNonceCalibrated = false;

    this.logger.debug(
      `Ark ChainCrypto was reset to height ${lastProcessedHeight}`
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

    let transactionMessage = transactionData.message || '';

    if (this.isNonceCalibrated) {
      this.nonceIndex++;
    } else {
      let currentTimestamp = transactionData.timestamp;

      let lastOutboundTransactionNonce = await this.getLastOutboundTransactionNonce(currentTimestamp);
      this.nonceIndex = lastOutboundTransactionNonce + 1n;

      // Look ahead to see if there is an existing record for this transaction;
      // if not, increment the nonceIndex until a match is found or until we run
      // out of transactions.
      let c = 0;
      let failedCalibration = false;
      while (true) {
        let foundMatchingTransaction = false;
        let nextOutboundTransactions = await this.getNextOutboundTransactions(currentTimestamp);
        for (let nextTransaction of nextOutboundTransactions) {
          if (nextTransaction.message === transactionMessage) {
            this.nonceIndex = BigInt(nextTransaction.nonce);
            foundMatchingTransaction = true;
            break;
          }
          this.nonceIndex = BigInt(nextTransaction.nonce) + 1n;
          currentTimestamp = nextTransaction.timestamp;
        }
        if (
          foundMatchingTransaction ||
          nextOutboundTransactions.length < this.maxTransactionsPerTimestamp
        ) {
          break;
        }
        if (++c > this.maxCalibrationLookAhead) {
          failedCalibration = true;
          break;
        }
      }
      if (failedCalibration) {
        throw new Error(
          `ChainCrypto nonce failed to calibrate because matching transaction was not found for message: ${
            transactionMessage
          }`
        );
      } else {
        this.isNonceCalibrated = true;
        this.logger.debug(`ChainCrypto nonce was calibrated to ${this.nonceIndex}`);
      }
    }

    let transferBuilder = Transactions.BuilderFactory.transfer();

    let preparedTxn = transferBuilder
      .version(2)
      .nonce(this.nonceIndex)
      .amount(transactionData.amount)
      .fee(transactionData.fee)
      .senderPublicKey(this.multisigPublicKey)
      .recipientId(transactionData.recipientAddress)
      .timestamp(transactionData.timestamp)
      .vendorField(transactionMessage)
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

  async getAccount() {
    return this.channel.invoke(`${this.moduleAlias}:getAccount`, {
      walletAddress: this.multisigAddress
    });
  }

  async getLastOutboundTransaction(fromTimestamp) {
    let i = 0;
    while (true) {
      i++;
      try {
        let transactions = await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactions`, {
          walletAddress: this.multisigAddress,
          fromTimestamp,
          limit: 1,
          order: 'desc'
        });
        return transactions[0];
      } catch (error) {
        this.logger.warn(`Failed to fetch last outbound transaction because of error: ${error.message}`);
        this.logger.debug(`Retry fetching last outbound transaction: Attempt #${i}`);
        await wait(FETCH_RETRY_DELAY);
      }
    }
  }

  async getNextOutboundTransactions(fromTimestamp) {
    let i = 0;
    while (true) {
      i++;
      try {
        let transactions = await this.channel.invoke(`${this.moduleAlias}:getOutboundTransactions`, {
          walletAddress: this.multisigAddress,
          fromTimestamp,
          limit: this.maxTransactionsPerTimestamp,
          order: 'asc'
        });
        return transactions;
      } catch (error) {
        this.logger.warn(`Failed to fetch next outbound transactions because of error: ${error.message}`);
        this.logger.debug(`Retry fetching next outbound transactions: Attempt #${i}`);
        await wait(FETCH_RETRY_DELAY);
      }
    }
  }

  async getLastOutboundTransactionNonce(fromTimestamp) {
    let lastOutboundTransaction = await this.getLastOutboundTransaction(fromTimestamp);
    return lastOutboundTransaction ? BigInt(lastOutboundTransaction.nonce) : 0n;
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
