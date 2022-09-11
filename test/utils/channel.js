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
      getBlocksBetweenHeights: (params) => {
        if (params.fromHeight >= 12) {
          return [];
        }
        return [
          {
            height: 10
          },
          {
            height: 11
          },
          {
            height: 12
          }
        ];
      },
      getOutboundTransactions: () => {
        return [
          {
            nonce: '3'
          },
          {
            nonce: '2'
          },
          {
            nonce: '1'
          }
        ];
      },
      getOutboundTransactionsFromBlock: () => {
        return [
          {
            id: '2ae4388f094b3d08ec11702a90fefd36bbb48b6d3eaef22db7882636e539f962',
            nonce: '2'
          },
          {
            id: '5aa69e2eee138aa8e5e9e0c4fbee773db9b131ccdf0957368ce335bbaee373e4',
            nonce: '3'
          }
        ];
      }
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
