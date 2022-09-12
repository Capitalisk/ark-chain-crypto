class Channel {
  constructor() {
    this.actionStubs = {
      getAccount: () => {
        return {
          nonce: '5',
          attributes: {
            multiSignature: {
              publicKeys: [
                '02bb3481404dfc0e441fa6dac4a5eae9c218c6145d09522e0ebe4aa944315dac26',
                '02a2390273dca76d9e2ec9b5b181294d7e1251f5f4e8e268ef062ec00c98e13480'
              ],
              min: 2
            }
          }
        };
      },
      getBlockAtHeight: () => {
        return {
          height: 100,
          timestamp: 10000000
        };
      },
      getOutboundTransactions: () => {
        return [];
      },
    };
  }

  async invoke(action, params) {
    let actionParts = action.split(':');
    let actionName = actionParts[1];
    if (!actionName) {
      throw new Error('Action name was not specified');
    }
    let actionHandler = this.actionStubs[actionName];
    if (!actionHandler) {
      throw new Error(`Action ${actionName} did not exists on mock channel`);
    }
    return actionHandler(params);
  }
}

module.exports = Channel;
