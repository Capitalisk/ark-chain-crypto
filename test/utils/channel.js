class Channel {
  async invoke() {
    return {
      address: 'ldposfacd5ebf967ebd87436bd5932a58168b9a1151e3',
      forgingPublicKey: '351b1c997046484dc443e2f728a4479d8523a3b7f088c577f628177e639ef2b1',
      nextForgingKeyIndex: 0,
      multisigPublicKey: '3ee9d5e74aa178ed7c6af4feb77430973c279a751be162cd3f669144b4a72fa2',
      nextMultisigKeyIndex: 0,
      sigPublicKey: 'facd5ebf967ebd87436bd5932a58168b9a1151e3ccfbb9bda9a8ab6cb546675e',
      nextSigKeyIndex: 0,
      balance: '10000000000000000',
      updateHeight: 1
    };
  }
}

module.exports = Channel;
