var config = {
    testnet: false, // this is adjusted page.h if needed. dont need to change manually
    stagenet: false, // this is adjusted page.h if needed. dont need to change manually
    coinUnitPlaces: 9,
    txMinConfirms: 4, // corresponds to CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE in Evolution
    txCoinbaseMinConfirms: 18, // corresponds to CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW in Evolution
    coinSymbol: 'EVOX',
    openAliasPrefix: "evox",
    coinName: 'Evolution',
    coinUriPrefix: 'evolution',
    addressPrefix: 0x6362, // ev...MainNET
    integratedAddressPrefix: 0x60e2, // evo...MainNET
    subAddressPrefix: 0x5e62, // evc...MainNET
    addressPrefixTestnet: 0x7de2, // ex...testnet
    integratedAddressPrefixTestnet: 0x7c62, // ext...testnet
    subAddressPrefixTestnet: 0x198762, // ett...testnet
    addressPrefixStagenet: 0x361, // ee...stageNet
    integratedAddressPrefixStagenet: 0x62e2, // evx...stageNet
    subAddressPrefixStagenet: 0x5a262, // evv...stageNet
    feePerKB: new JSBigInt('20000'),//20^10 - for testnet its not used, as fee is dynamic.
    dustThreshold: new JSBigInt('10000'),//10^10 used for choosing outputs/change - we decompose all the way down if the receiver wants now regardless of threshold
    txChargeRatio: 0.5,
    defaultMixin: 11, // minimum mixin for hardfork v15
    txChargeAddress: '',
    idleTimeout: 30,
    idleWarningDuration: 20,
    maxBlockNumber: 500000000,
    avgBlockTime: 120,
    debugMode: false
};
