// Copyright (c) 2014-2017, MyMonero.com
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Original Author: Lucas Jones
// Modified to remove jQuery dep and support modular inclusion of deps by Paul Shapiro (2016)
// Modified by luigi1111 2017

var cnUtil = (function(initConfig) {

    var config = {};// shallow copy of initConfig

    for (var key in initConfig) {
        config[key] = initConfig[key];
    }

    config.coinUnits = new JSBigInt(10).pow(config.coinUnitPlaces);

    var HASH_STATE_BYTES = 200;
    var HASH_SIZE = 32;
    var ADDRESS_CHECKSUM_SIZE = 4;
    var INTEGRATED_ID_SIZE = 8;
    var ENCRYPTED_PAYMENT_ID_TAIL = 141;
    var CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = config.addressPrefix;
    var CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = config.integratedAddressPrefix;
    var CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = config.subAddressPrefix;

    if (config.testnet === true)
    {
        CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = config.addressPrefixTestnet;
        CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = config.integratedAddressPrefixTestnet;
        CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = config.subAddressPrefixTestnet;
    }

    if (config.stagenet === true)
    {
        CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = config.addressPrefixStagenet;
        CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = config.integratedAddressPrefixStagenet;
        CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = config.subAddressPrefixStagenet;
    }

    var UINT64_MAX = new JSBigInt(2).pow(64);
    var CURRENT_TX_VERSION = 2;
    var OLD_TX_VERSION = 1;
    var RCTTypeFull = 1;
    var RCTTypeSimple = 2;
    var RCTTypeFullBulletproof = 3;
    var RCTTypeSimpleBulletproof = 4;
    var RCTTypeBulletproof = 5;
    var TX_EXTRA_NONCE_MAX_COUNT = 255;
    var TX_EXTRA_TAGS = {
        PADDING: '00',
        PUBKEY: '01',
        NONCE: '02',
        MERGE_MINING: '03'
    };
    var TX_EXTRA_NONCE_TAGS = {
        PAYMENT_ID: '00',
        ENCRYPTED_PAYMENT_ID: '01'
    };
    var KEY_SIZE = 32;
    var STRUCT_SIZES = {
        GE_P3: 160,
        GE_P2: 120,
        GE_P1P1: 160,
        GE_CACHED: 160,
        EC_SCALAR: 32,
        EC_POINT: 32,
        KEY_IMAGE: 32,
        GE_DSMP: 160 * 8, // ge_cached * 8
        SIGNATURE: 64 // ec_scalar * 2
    };

    //RCT vars
    var H = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"; //base H for amounts
    var l = JSBigInt("7237005577332262213973186563042994240857116359379907606001950938285454250989"); //curve order (not RCT specific)
    var lminus2 = l.subtract(2);
    var I = "0100000000000000000000000000000000000000000000000000000000000000"; //identity element
    var Z = "0000000000000000000000000000000000000000000000000000000000000000"; //zero scalar
    //H2 object to speed up some operations
    var H2 = ["8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94", "8faa448ae4b3e2bb3d4d130909f55fcd79711c1c83cdbccadd42cbe1515e8712",
        "12a7d62c7791654a57f3e67694ed50b49a7d9e3fc1e4c7a0bde29d187e9cc71d", "789ab9934b49c4f9e6785c6d57a498b3ead443f04f13df110c5427b4f214c739",
        "771e9299d94f02ac72e38e44de568ac1dcb2edc6edb61f83ca418e1077ce3de8", "73b96db43039819bdaf5680e5c32d741488884d18d93866d4074a849182a8a64",
        "8d458e1c2f68ebebccd2fd5d379f5e58f8134df3e0e88cad3d46701063a8d412", "09551edbe494418e81284455d64b35ee8ac093068a5f161fa6637559177ef404",
        "d05a8866f4df8cee1e268b1d23a4c58c92e760309786cdac0feda1d247a9c9a7", "55cdaad518bd871dd1eb7bc7023e1dc0fdf3339864f88fdd2de269fe9ee1832d",
        "e7697e951a98cfd5712b84bbe5f34ed733e9473fcb68eda66e3788df1958c306", "f92a970bae72782989bfc83adfaa92a4f49c7e95918b3bba3cdc7fe88acc8d47",
        "1f66c2d491d75af915c8db6a6d1cb0cd4f7ddcd5e63d3ba9b83c866c39ef3a2b", "3eec9884b43f58e93ef8deea260004efea2a46344fc5965b1a7dd5d18997efa7",
        "b29f8f0ccb96977fe777d489d6be9e7ebc19c409b5103568f277611d7ea84894", "56b1f51265b9559876d58d249d0c146d69a103636699874d3f90473550fe3f2c",
        "1d7a36575e22f5d139ff9cc510fa138505576b63815a94e4b012bfd457caaada", "d0ac507a864ecd0593fa67be7d23134392d00e4007e2534878d9b242e10d7620",
        "f6c6840b9cf145bb2dccf86e940be0fc098e32e31099d56f7fe087bd5deb5094", "28831a3340070eb1db87c12e05980d5f33e9ef90f83a4817c9f4a0a33227e197",
        "87632273d629ccb7e1ed1a768fa2ebd51760f32e1c0b867a5d368d5271055c6e", "5c7b29424347964d04275517c5ae14b6b5ea2798b573fc94e6e44a5321600cfb",
        "e6945042d78bc2c3bd6ec58c511a9fe859c0ad63fde494f5039e0e8232612bd5", "36d56907e2ec745db6e54f0b2e1b2300abcb422e712da588a40d3f1ebbbe02f6",
        "34db6ee4d0608e5f783650495a3b2f5273c5134e5284e4fdf96627bb16e31e6b", "8e7659fb45a3787d674ae86731faa2538ec0fdf442ab26e9c791fada089467e9",
        "3006cf198b24f31bb4c7e6346000abc701e827cfbb5df52dcfa42e9ca9ff0802", "f5fd403cb6e8be21472e377ffd805a8c6083ea4803b8485389cc3ebc215f002a",
        "3731b260eb3f9482e45f1c3f3b9dcf834b75e6eef8c40f461ea27e8b6ed9473d", "9f9dab09c3f5e42855c2de971b659328a2dbc454845f396ffc053f0bb192f8c3",
        "5e055d25f85fdb98f273e4afe08464c003b70f1ef0677bb5e25706400be620a5", "868bcf3679cb6b500b94418c0b8925f9865530303ae4e4b262591865666a4590",
        "b3db6bd3897afbd1df3f9644ab21c8050e1f0038a52f7ca95ac0c3de7558cb7a", "8119b3a059ff2cac483e69bcd41d6d27149447914288bbeaee3413e6dcc6d1eb",
        "10fc58f35fc7fe7ae875524bb5850003005b7f978c0c65e2a965464b6d00819c", "5acd94eb3c578379c1ea58a343ec4fcff962776fe35521e475a0e06d887b2db9",
        "33daf3a214d6e0d42d2300a7b44b39290db8989b427974cd865db011055a2901", "cfc6572f29afd164a494e64e6f1aeb820c3e7da355144e5124a391d06e9f95ea",
        "d5312a4b0ef615a331f6352c2ed21dac9e7c36398b939aec901c257f6cbc9e8e", "551d67fefc7b5b9f9fdbf6af57c96c8a74d7e45a002078a7b5ba45c6fde93e33",
        "d50ac7bd5ca593c656928f38428017fc7ba502854c43d8414950e96ecb405dc3", "0773e18ea1be44fe1a97e239573cfae3e4e95ef9aa9faabeac1274d3ad261604",
        "e9af0e7ca89330d2b8615d1b4137ca617e21297f2f0ded8e31b7d2ead8714660", "7b124583097f1029a0c74191fe7378c9105acc706695ed1493bb76034226a57b",
        "ec40057b995476650b3db98e9db75738a8cd2f94d863b906150c56aac19caa6b", "01d9ff729efd39d83784c0fe59c4ae81a67034cb53c943fb818b9d8ae7fc33e5",
        "00dfb3c696328c76424519a7befe8e0f6c76f947b52767916d24823f735baf2e", "461b799b4d9ceea8d580dcb76d11150d535e1639d16003c3fb7e9d1fd13083a8",
        "ee03039479e5228fdc551cbde7079d3412ea186a517ccc63e46e9fcce4fe3a6c", "a8cfb543524e7f02b9f045acd543c21c373b4c9b98ac20cec417a6ddb5744e94",
        "932b794bf89c6edaf5d0650c7c4bad9242b25626e37ead5aa75ec8c64e09dd4f", "16b10c779ce5cfef59c7710d2e68441ea6facb68e9b5f7d533ae0bb78e28bf57",
        "0f77c76743e7396f9910139f4937d837ae54e21038ac5c0b3fd6ef171a28a7e4", "d7e574b7b952f293e80dde905eb509373f3f6cd109a02208b3c1e924080a20ca",
        "45666f8c381e3da675563ff8ba23f83bfac30c34abdde6e5c0975ef9fd700cb9", "b24612e454607eb1aba447f816d1a4551ef95fa7247fb7c1f503020a7177f0dd",
        "7e208861856da42c8bb46a7567f8121362d9fb2496f131a4aa9017cf366cdfce", "5b646bff6ad1100165037a055601ea02358c0f41050f9dfe3c95dccbd3087be0",
        "746d1dccfed2f0ff1e13c51e2d50d5324375fbd5bf7ca82a8931828d801d43ab", "cb98110d4a6bb97d22feadbc6c0d8930c5f8fc508b2fc5b35328d26b88db19ae",
        "60b626a033b55f27d7676c4095eababc7a2c7ede2624b472e97f64f96b8cfc0e", "e5b52bc927468df71893eb8197ef820cf76cb0aaf6e8e4fe93ad62d803983104",
        "056541ae5da9961be2b0a5e895e5c5ba153cbb62dd561a427bad0ffd41923199", "f8fef05a3fa5c9f3eba41638b247b711a99f960fe73aa2f90136aeb20329b888"];

    //begin rct new functions
    //creates a Pedersen commitment from an amount (in scalar form) and a mask
    //C = bG + aH where b = mask, a = amount

    //yay bulletproofs
    //begin bulletproof vars
    var maxN = 64;
    var BULLETPROOF_MAX_OUTPUTS = 16;
    var maxM = BULLETPROOF_MAX_OUTPUTS;
    var TWO = d2s("2");
    var INV_EIGHT = "792fdce229e50661d0da1c7db39dd30700000000000000000000000000000006";
    var Hi = [], Gi = []; //consider precomputing -- takes approximately 500ms to generate

    function commit(amount, mask){
        if (!valid_hex(mask) || mask.length !== 64 || !valid_hex(amount) || amount.length !== 64){
            throw "invalid amount or mask!";
        }
        var C = this.ge_double_scalarmult_base_vartime(amount, H, mask);
        return C;
    }

    function zeroCommit(amount){
        if (!valid_hex(amount) || amount.length !== 64){
            throw "invalid amount!";
        }
        var C = this.ge_double_scalarmult_base_vartime(amount, H, I);
        return C;
    }

    this.decode_rct_ecdh = function(ecdh, key) {
        var first = this.hash_to_scalar(key);
        var second = this.hash_to_scalar(first);
        return {
            "mask": this.sc_sub(ecdh.mask, first),
            "amount": this.sc_sub(ecdh.amount, second)
        };
    };

    this.encode_rct_ecdh = function(ecdh, key) {
        var first = this.hash_to_scalar(key);
        var second = this.hash_to_scalar(first);
        return {
            "mask": this.sc_add(ecdh.mask, first),
            "amount": this.sc_add(ecdh.amount, second)
        };
    };

    //switch byte order for hex string
    function swapEndian(hex){
        if (hex.length % 2 !== 0){return "length must be a multiple of 2!";}
        var data = "";
        for (var i=1; i <= hex.length / 2; i++){
            data += hex.substr(0 - 2 * i, 2);
        }
        return data;
    }

    //switch byte order charwise
    function swapEndianC(string){
        var data = "";
        for (var i=1; i <= string.length; i++){
            data += string.substr(0 - i, 1);
        }
        return data;
    }

    //for most uses you'll also want to swapEndian after conversion
    //mainly to convert integer "scalars" to usable hexadecimal strings
    function d2h(integer){
        if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
        var padding = "";
        for (i = 0; i < 63; i++){
            padding += "0";
        }
        return (padding + JSBigInt(integer).toString(16).toLowerCase()).slice(-64);
    }

    //integer (string) to scalar
    function d2s(integer){
        return swapEndian(d2h(integer));
    }

    //scalar to integer (string)
    function s2d(scalar){
        return JSBigInt.parse(swapEndian(scalar), 16).toString();
    }

    //convert integer string to 64bit "binary" little-endian string
    function d2b(integer){
        if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
        var padding = "";
        for (i = 0; i < 63; i++){
            padding += "0";
        }
        var a = new JSBigInt(integer);
        if (a.toString(2).length > 64){throw "amount overflows uint64!";}
        return swapEndianC((padding + a.toString(2)).slice(-64));
    }

    //convert integer string to 64bit base 4 little-endian string
    function d2b4(integer){
        if (typeof integer !== "string" && integer.toString().length > 15){throw "integer should be entered as a string for precision";}
        var padding = "";
        for (i = 0; i < 31; i++){
            padding += "0";
        }
        var a = new JSBigInt(integer);
        if (a.toString(2).length > 64){throw "amount overflows uint64!";}
        return swapEndianC((padding + a.toString(4)).slice(-32));
    }

    this.invert = function(a) {
        return d2s(JSBigInt(s2d(a)).modPow(lminus2, l).toString());
    };

    //end rct new functions

    this.valid_hex = function(hex) {
        var exp = new RegExp("[0-9a-fA-F]{" + hex.length + "}");
        return exp.test(hex);
    };

    //simple exclusive or function for two hex inputs
    this.hex_xor = function(hex1, hex2) {
        if (!hex1 || !hex2 || hex1.length !== hex2.length || hex1.length % 2 !== 0 || hex2.length % 2 !== 0){throw "Hex string(s) is/are invalid!";}
        var bin1 = hextobin(hex1);
        var bin2 = hextobin(hex2);
        var xor = new Uint8Array(bin1.length);
        for (i = 0; i < xor.length; i++){
            xor[i] = bin1[i] ^ bin2[i];
        }
        return bintohex(xor);
    };

    function hextobin(hex) {
        if (hex.length % 2 !== 0) throw "Hex string has invalid length!";
        var res = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length / 2; ++i) {
            res[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return res;
    }

    function bintohex(bin) {
        var out = [];
        for (var i = 0; i < bin.length; ++i) {
            out.push(("0" + bin[i].toString(16)).slice(-2));
        }
        return out.join("");
    }

    // Generate a 256-bit crypto random
    this.rand_32 = function() {
        return mn_random(256);
    };

    // Generate a 128-bit crypto random
    this.rand_16 = function() {
        return mn_random(128);
    };

    // Generate a 64-bit crypto random
    this.rand_8 = function() {
        return mn_random(64);
    };

    this.encode_varint = function(i) {
        i = new JSBigInt(i);
        var out = '';
        // While i >= b10000000
        while (i.compare(0x80) >= 0) {
            // out.append i & b01111111 | b10000000
            out += ("0" + ((i.lowVal() & 0x7f) | 0x80).toString(16)).slice(-2);
            i = i.divide(new JSBigInt(2).pow(7));
        }
        out += ("0" + i.toJSValue().toString(16)).slice(-2);
        return out;
    };

    this.sc_reduce = function(hex) {
        var input = hextobin(hex);
        if (input.length !== 64) {
            throw "sc_reduce: Invalid hextobin(hex) input length";
        }
        var mem = Module._malloc(64);
        Module.HEAPU8.set(input, mem);
        Module.ccall('sc_reduce', 'void', ['number'], [mem]);
        var output = Module.HEAPU8.subarray(mem, mem + 64);
        Module._free(mem);
        return bintohex(output);
    };

    this.sc_reduce32 = function(hex) {
        var input = hextobin(hex);
        if (input.length !== 32) {
            throw "sc_reduce32: Invalid hextobin(hex) input length";
        }
        var mem = Module._malloc(32);
        Module.HEAPU8.set(input, mem);
        Module.ccall('sc_reduce32', 'void', ['number'], [mem]);
        var output = Module.HEAPU8.subarray(mem, mem + 32);
        Module._free(mem);
        return bintohex(output);
    };

    this.cn_fast_hash = function(input, inlen) {
        /*if (inlen === undefined || !inlen) {
            inlen = Math.floor(input.length / 2);
        }*/
        if (input.length % 2 !== 0 || !this.valid_hex(input)) {
            throw "cn_fast_hash: Input invalid";
        }
        //update to use new keccak impl (approx 45x faster)
        //var state = this.keccak(input, inlen, HASH_STATE_BYTES);
        //return state.substr(0, HASH_SIZE * 2);
        return keccak_256(hextobin(input));
    };

    //many functions below are commented out now, and duplicated with the faster nacl impl --luigi1111
    // to be removed completely later
    /*this.sec_key_to_pub = function(sec) {
        var input = hextobin(sec);
        if (input.length !== 32) {
            throw "Invalid input length";
        }
        var input_mem = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(input, input_mem);
        var ge_p3 = Module._malloc(STRUCT_SIZES.GE_P3);
        var out_mem = Module._malloc(KEY_SIZE);
        Module.ccall('ge_scalarmult_base', 'void', ['number', 'number'], [ge_p3, input_mem]);
        Module.ccall('ge_p3_tobytes', 'void', ['number', 'number'], [out_mem, ge_p3]);
        var output = Module.HEAPU8.subarray(out_mem, out_mem + KEY_SIZE);
        Module._free(ge_p3);
        Module._free(input_mem);
        Module._free(out_mem);
        return bintohex(output);
    };*/

    this.sec_key_to_pub = function(sec) {
        if (sec.length !== 64) {
            throw "sec_key_to_pub: Invalid sec length";
        }
        return bintohex(nacl.ll.ge_scalarmult_base(hextobin(sec)));
    };

    //alias
    this.ge_scalarmult_base = function(sec) {
        return this.sec_key_to_pub(sec);
    };

    //accepts arbitrary point, rather than G
    /*this.ge_scalarmult = function(pub, sec) {
        if (pub.length !== 64 || sec.length !== 64) {
            throw "Invalid input length";
        }
        var pub_b = hextobin(pub);
        var sec_b = hextobin(sec);
        var pub_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(pub_b, pub_m);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(sec_b, sec_m);
        var ge_p3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var ge_p2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [ge_p3_m, pub_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        Module.ccall("ge_scalarmult", "void", ["number", "number", "number"], [ge_p2_m, sec_m, ge_p3_m]);
        var derivation_m = Module._malloc(KEY_SIZE);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [derivation_m, ge_p2_m]);
        var res = Module.HEAPU8.subarray(derivation_m, derivation_m + KEY_SIZE);
        Module._free(pub_m);
        Module._free(sec_m);
        Module._free(ge_p3_m);
        Module._free(ge_p2_m);
        Module._free(derivation_m);
        return bintohex(res);
    };*/
    this.ge_scalarmult = function(pub, sec) {
        if (pub.length !== 64 || sec.length !== 64) {
            throw "ge_scalarmult: Invalid pub or sec input lengths";
        }
        return bintohex(nacl.ll.ge_scalarmult(hextobin(pub), hextobin(sec)));
    };

    this.pubkeys_to_string = function(spend, view) {
        var prefix = this.encode_varint(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
        var data = prefix + spend + view;
        var checksum = this.cn_fast_hash(data);
        return cnBase58.encode(data + checksum.slice(0, ADDRESS_CHECKSUM_SIZE * 2));
    };

    this.get_account_integrated_address = function(address, payment_id8) {
        var decoded_address = decode_address(address);

        var prefix = this.encode_varint(CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
        var data = prefix + decoded_address.spend  + decoded_address.view + payment_id8;

        var checksum = this.cn_fast_hash(data);

        return cnBase58.encode(data + checksum.slice(0, ADDRESS_CHECKSUM_SIZE * 2));
    };


    this.decrypt_payment_id = function(payment_id8, tx_public_key, acc_prv_view_key) {
        if (payment_id8.length !== 16) throw "decrypt_payment_id: Invalid payment_id8 length!";

        var key_derivation = this.generate_key_derivation(tx_public_key, acc_prv_view_key);

        var pid_key = this.cn_fast_hash(key_derivation + ENCRYPTED_PAYMENT_ID_TAIL.toString(16)).slice(0, INTEGRATED_ID_SIZE * 2);

        var decrypted_payment_id = this.hex_xor(payment_id8, pid_key);

        return decrypted_payment_id;
    }

    // Generate keypair from seed
    this.generate_keys_old = function(seed) {
        if (seed.length !== 64) throw "Invalid input length!";
        var sec = this.sc_reduce32(seed);
        var pub = this.sec_key_to_pub(sec);
        return {
            'sec': sec,
            'pub': pub
        };
    };

    // Generate keypair from seed 2
    // as in simplewallet
    this.generate_keys = function(seed) {
        if (seed.length !== 64) throw "generate_keys: Invalid seed input length!";
        var sec = this.sc_reduce32(seed);
        var pub = this.sec_key_to_pub(sec);
        return {
            'sec': sec,
            'pub': pub
        };
    };

    this.random_keypair = function() {
        return this.generate_keys(this.rand_32());
    };

    // Random 32-byte ec scalar
    this.random_scalar = function() {
        //var rand = this.sc_reduce(mn_random(64 * 8));
        //return rand.slice(0, STRUCT_SIZES.EC_SCALAR * 2);
        return this.sc_reduce32(this.rand_32());
    };

    /* no longer used
    this.keccak = function(hex, inlen, outlen) {
        var input = hextobin(hex);
        if (input.length !== inlen) {
            throw "Invalid input length";
        }
        if (outlen <= 0) {
            throw "Invalid output length";
        }
        var input_mem = Module._malloc(inlen);
        Module.HEAPU8.set(input, input_mem);
        var out_mem = Module._malloc(outlen);
        Module._keccak(input_mem, inlen | 0, out_mem, outlen | 0);
        var output = Module.HEAPU8.subarray(out_mem, out_mem + outlen);
        Module._free(input_mem);
        Module._free(out_mem);
        return bintohex(output);
    };*/


    this.create_address = function(seed) {
        var keys = {};
        var first;
        if (seed.length !== 64) {
            first = this.cn_fast_hash(seed);
        } else {
            first = seed; //only input reduced seeds or this will not give you the result you want
        }

        keys.spend = this.generate_keys(first);
        if (seed.length !== 64) {
            var second = this.cn_fast_hash(first);
        } else {
            var second = this.cn_fast_hash(keys.spend.sec);
        }

        keys.view = this.generate_keys(second);
        keys.public_addr = this.pubkeys_to_string(keys.spend.pub, keys.view.pub);
        return keys;
    };


    this.create_addr_prefix = function(seed) {
        var first;
        if (seed.length !== 64) {
            first = this.cn_fast_hash(seed);
        } else {
            first = seed;
        }
        var spend = this.generate_keys(first);
        var prefix = this.encode_varint(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
        return cnBase58.encode(prefix + spend.pub).slice(0, 44);
    };

    this.is_subaddress = function(address) {
        var dec = cnBase58.decode(address);
        var expectedPrefixSub = this.encode_varint(CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
        var prefix = dec.slice(0, expectedPrefixSub.length);
        return (prefix === expectedPrefixSub);
    }

    this.decode_address = function(address) {
        var dec = cnBase58.decode(address);
        var expectedPrefix = this.encode_varint(CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
        var expectedPrefixInt = this.encode_varint(CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX);
        var expectedPrefixSub = this.encode_varint(CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX);
        var prefix = dec.slice(0, expectedPrefix.length);
        if (prefix !== expectedPrefix && prefix !== expectedPrefixInt && prefix !== expectedPrefixSub) {
            throw "Invalid address prefix";
        }
        dec = dec.slice(expectedPrefix.length);
        var spend = dec.slice(0, 64);
        var view = dec.slice(64, 128);
        if (prefix === expectedPrefixInt){
            var intPaymentId = dec.slice(128, 128 + (INTEGRATED_ID_SIZE * 2));
            var checksum = dec.slice(128 + (INTEGRATED_ID_SIZE * 2), 128 + (INTEGRATED_ID_SIZE * 2) + (ADDRESS_CHECKSUM_SIZE * 2));
            var expectedChecksum = this.cn_fast_hash(prefix + spend + view + intPaymentId).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
        } else if (prefix === expectedPrefix) {
            var checksum = dec.slice(128, 128 + (ADDRESS_CHECKSUM_SIZE * 2));
            var expectedChecksum = this.cn_fast_hash(prefix + spend + view).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
        } else {
            // if its not regular address, nor integrated, than it must be subaddress
            var checksum = dec.slice(128, 128 + (ADDRESS_CHECKSUM_SIZE * 2));
            var expectedChecksum = this.cn_fast_hash(prefix + spend + view).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
        }
        if (checksum !== expectedChecksum) {
            throw "Invalid checksum";
        }
        if (intPaymentId){
            return {
                spend: spend,
                view: view,
                intPaymentId: intPaymentId
            };
        } else {
            return {
                spend: spend,
                view: view
            };
        }
    };

    this.valid_keys = function(view_pub, view_sec, spend_pub, spend_sec) {
        var expected_view_pub = this.sec_key_to_pub(view_sec);
        var expected_spend_pub = this.sec_key_to_pub(spend_sec);
        return (expected_spend_pub === spend_pub) && (expected_view_pub === view_pub);
    };

    this.hash_to_scalar = function(buf) {
        var hash = this.cn_fast_hash(buf);
        var scalar = this.sc_reduce32(hash);
        return scalar;
    };

    /*this.generate_key_derivation = function(pub, sec) {
        if (pub.length !== 64 || sec.length !== 64) {
            throw "Invalid input length";
        }
        var pub_b = hextobin(pub);
        var sec_b = hextobin(sec);
        var pub_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(pub_b, pub_m);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(sec_b, sec_m);
        var ge_p3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var ge_p2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var ge_p1p1_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [ge_p3_m, pub_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        Module.ccall("ge_scalarmult", "void", ["number", "number", "number"], [ge_p2_m, sec_m, ge_p3_m]);
        Module.ccall("ge_mul8", "void", ["number", "number"], [ge_p1p1_m, ge_p2_m]);
        Module.ccall("ge_p1p1_to_p2", "void", ["number", "number"], [ge_p2_m, ge_p1p1_m]);
        var derivation_m = Module._malloc(KEY_SIZE);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [derivation_m, ge_p2_m]);
        var res = Module.HEAPU8.subarray(derivation_m, derivation_m + KEY_SIZE);
        Module._free(pub_m);
        Module._free(sec_m);
        Module._free(ge_p3_m);
        Module._free(ge_p2_m);
        Module._free(ge_p1p1_m);
        Module._free(derivation_m);
        return bintohex(res);
    };*/

    this.generate_key_derivation = function(pub, sec) {
        if (pub.length !== 64 || sec.length !== 64) {
            throw "generate_key_derivation: Invalid pub or sec keys lengths";
        }
        var P = this.ge_scalarmult(pub, sec);
        return this.ge_scalarmult(P, d2s(8)); //mul8 to ensure group
    };

    this.derivation_to_scalar = function(derivation, output_index) {
        var buf = "";
        if (derivation.length !== (STRUCT_SIZES.EC_POINT * 2)) {
            throw "derivation_to_scalar: Invalid derivation length!";
        }
        buf += derivation;
        var enc = encode_varint(output_index);
        if (enc.length > 10 * 2) {
            throw "output_index didn't fit in 64-bit varint";
        }
        buf += enc;
        return this.hash_to_scalar(buf);
    };

    this.derive_secret_key = function(derivation, out_index, sec) {
        if (derivation.length !== 64 || sec.length !== 64) {
            throw "derive_secret_key: Invalid derivation or sec input length!";
        }
        var scalar_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar_b = hextobin(this.derivation_to_scalar(derivation, out_index));
        Module.HEAPU8.set(scalar_b, scalar_m);
        var base_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sec), base_m);
        var derived_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.ccall("sc_add", "void", ["number", "number", "number"], [derived_m, base_m, scalar_m]);
        var res = Module.HEAPU8.subarray(derived_m, derived_m + STRUCT_SIZES.EC_SCALAR);
        Module._free(scalar_m);
        Module._free(base_m);
        Module._free(derived_m);
        return bintohex(res);
    };

    /*this.derive_public_key = function(derivation, out_index, pub) {
        if (derivation.length !== 64 || pub.length !== 64) {
            throw "Invalid input length!";
        }
        var derivation_m = Module._malloc(KEY_SIZE);
        var derivation_b = hextobin(derivation);
        Module.HEAPU8.set(derivation_b, derivation_m);
        var base_m = Module._malloc(KEY_SIZE);
        var base_b = hextobin(pub);
        Module.HEAPU8.set(base_b, base_m);
        var point1_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var point3_m = Module._malloc(STRUCT_SIZES.GE_CACHED);
        var point4_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var point5_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var derived_key_m = Module._malloc(KEY_SIZE);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [point1_m, base_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        var scalar_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar_b = hextobin(this.derivation_to_scalar(bintohex(Module.HEAPU8.subarray(derivation_m, derivation_m + STRUCT_SIZES.EC_POINT)), out_index));
        Module.HEAPU8.set(scalar_b, scalar_m);
        Module.ccall("ge_scalarmult_base", "void", ["number", "number"], [point2_m, scalar_m]);
        Module.ccall("ge_p3_to_cached", "void", ["number", "number"], [point3_m, point2_m]);
        Module.ccall("ge_add", "void", ["number", "number", "number"], [point4_m, point1_m, point3_m]);
        Module.ccall("ge_p1p1_to_p2", "void", ["number", "number"], [point5_m, point4_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [derived_key_m, point5_m]);
        var res = Module.HEAPU8.subarray(derived_key_m, derived_key_m + KEY_SIZE);
        Module._free(derivation_m);
        Module._free(base_m);
        Module._free(scalar_m);
        Module._free(point1_m);
        Module._free(point2_m);
        Module._free(point3_m);
        Module._free(point4_m);
        Module._free(point5_m);
        Module._free(derived_key_m);
        return bintohex(res);
    };*/

    this.derive_public_key = function(derivation, out_index, pub) {
        if (derivation.length !== 64 || pub.length !== 64) {
            throw "derive_public_key: Invalid derivation or pub key input lengths!";
        }
        var s = this.derivation_to_scalar(derivation, out_index);
        return bintohex(nacl.ll.ge_add(hextobin(pub), hextobin(this.ge_scalarmult_base(s))));
    };

    this.hash_to_ec = function(key) {
        if (key.length !== (KEY_SIZE * 2)) {
            throw "hash_to_ec: Invalid key input length";
        }
        var h_m = Module._malloc(HASH_SIZE);
        var point_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var res_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var hash = hextobin(this.cn_fast_hash(key, KEY_SIZE));
        Module.HEAPU8.set(hash, h_m);
        Module.ccall("ge_fromfe_frombytes_vartime", "void", ["number", "number"], [point_m, h_m]);
        Module.ccall("ge_mul8", "void", ["number", "number"], [point2_m, point_m]);
        Module.ccall("ge_p1p1_to_p3", "void", ["number", "number"], [res_m, point2_m]);
        var res = Module.HEAPU8.subarray(res_m, res_m + STRUCT_SIZES.GE_P3);
        Module._free(h_m);
        Module._free(point_m);
        Module._free(point2_m);
        Module._free(res_m);
        return bintohex(res);
    };

    //returns a 32 byte point via "ge_p3_tobytes" rather than a 160 byte "p3", otherwise same as above;
    this.hash_to_ec_2 = function(key) {
        if (key.length !== (KEY_SIZE * 2)) {
            throw "hash_to_ec_2: Invalid key input length";
        }
        var h_m = Module._malloc(HASH_SIZE);
        var point_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var res_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var hash = hextobin(this.cn_fast_hash(key, KEY_SIZE));
        var res2_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hash, h_m);
        Module.ccall("ge_fromfe_frombytes_vartime", "void", ["number", "number"], [point_m, h_m]);
        Module.ccall("ge_mul8", "void", ["number", "number"], [point2_m, point_m]);
        Module.ccall("ge_p1p1_to_p3", "void", ["number", "number"], [res_m, point2_m]);
        Module.ccall("ge_p3_tobytes", "void", ["number", "number"], [res2_m, res_m]);
        var res = Module.HEAPU8.subarray(res2_m, res2_m + KEY_SIZE);
        Module._free(h_m);
        Module._free(point_m);
        Module._free(point2_m);
        Module._free(res_m);
        Module._free(res2_m);
        return bintohex(res);
    };

    this.generate_key_image_2 = function(pub, sec) {
        if (!pub || !sec || pub.length !== 64 || sec.length !== 64) {
            throw "generate_key_image_2: Invalid pub or sec keys input length";
        }
        var pub_m = Module._malloc(KEY_SIZE);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(pub), pub_m);
        Module.HEAPU8.set(hextobin(sec), sec_m);
        if (Module.ccall("sc_check", "number", ["number"], [sec_m]) !== 0) {
            throw "sc_check(sec) != 0";
        }
        var point_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var point2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var point_b = hextobin(this.hash_to_ec(pub));
        Module.HEAPU8.set(point_b, point_m);
        var image_m = Module._malloc(STRUCT_SIZES.KEY_IMAGE);
        Module.ccall("ge_scalarmult", "void", ["number", "number", "number"], [point2_m, sec_m, point_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [image_m, point2_m]);
        var res = Module.HEAPU8.subarray(image_m, image_m + STRUCT_SIZES.KEY_IMAGE);
        Module._free(pub_m);
        Module._free(sec_m);
        Module._free(point_m);
        Module._free(point2_m);
        Module._free(image_m);
        return bintohex(res);
    };

    this.generate_key_image = function(tx_pub, view_sec, spend_pub, spend_sec, output_index) {
        if (tx_pub.length !== 64) {
            throw "Invalid tx_pub length";
        }
        if (view_sec.length !== 64) {
            throw "Invalid view_sec length";
        }
        if (spend_pub.length !== 64) {
            throw "Invalid spend_pub length";
        }
        if (spend_sec.length !== 64) {
            throw "Invalid spend_sec length";
        }
        var recv_derivation = this.generate_key_derivation(tx_pub, view_sec);
        var ephemeral_pub = this.derive_public_key(recv_derivation, output_index, spend_pub);
        var ephemeral_sec = this.derive_secret_key(recv_derivation, output_index, spend_sec);
        var k_image = this.generate_key_image_2(ephemeral_pub, ephemeral_sec);
        return {
            ephemeral_pub: ephemeral_pub,
            key_image: k_image
        };
    };

    this.generate_key_image_helper_rct = function(keys, tx_pub_key, out_index, enc_mask) {
        var recv_derivation = this.generate_key_derivation(tx_pub_key, keys.view.sec);
        if (!recv_derivation) throw "Failed to generate key image";

        var mask;

        if (enc_mask === I)
        {
            // this is for ringct coinbase txs (rct type 0). they are ringct tx that have identity mask
            mask = enc_mask; // enc_mask is idenity mask returned by backend.
        }
        else
        {
            // for other ringct types or for non-ringct txs to this.
            mask = enc_mask ? sc_sub(enc_mask, hash_to_scalar(derivation_to_scalar(recv_derivation, out_index))) : I; //decode mask, or d2s(1) if no mask
        }

        var ephemeral_pub = this.derive_public_key(recv_derivation, out_index, keys.spend.pub);
        if (!ephemeral_pub) throw "Failed to generate key image";
        var ephemeral_sec = this.derive_secret_key(recv_derivation, out_index, keys.spend.sec);
        var image = this.generate_key_image_2(ephemeral_pub, ephemeral_sec);
        return {
            in_ephemeral: {
                pub: ephemeral_pub,
                sec: ephemeral_sec,
                mask: mask
            },
            image: image
        };
    };

    //curve and scalar functions; split out to make their host functions cleaner and more readable
    //inverts X coordinate -- this seems correct ^_^ -luigi1111
    this.ge_neg = function(point) {
      if (point.length !== 64){
        throw "expected 64 char hex string";
      }
      return point.slice(0,62) + ((parseInt(point.slice(62,63), 16) + 8) % 16).toString(16) + point.slice(63,64);
    };

    //adds two points together, order does not matter
    /*this.ge_add2 = function(point1, point2) {
        var point1_m = Module._malloc(KEY_SIZE);
        var point2_m = Module._malloc(KEY_SIZE);
        var point1_m2 = Module._malloc(STRUCT_SIZES.GE_P3);
        var point2_m2 = Module._malloc(STRUCT_SIZES.GE_P3);
        Module.HEAPU8.set(hextobin(point1), point1_m);
        Module.HEAPU8.set(hextobin(point2), point2_m);
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [point1_m2, point1_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        if (Module.ccall("ge_frombytes_vartime", "bool", ["number", "number"], [point2_m2, point2_m]) !== 0) {
            throw "ge_frombytes_vartime returned non-zero error code";
        }
        var sum_m = Module._malloc(KEY_SIZE);
        var p2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var p1_m = Module._malloc(STRUCT_SIZES.GE_P1P1);
        var p3_m = Module._malloc(STRUCT_SIZES.GE_CACHED);
        Module.ccall("ge_p3_to_cached", "void", ["number", "number"], [p3_m, point2_m2]);
        Module.ccall("ge_add", "void", ["number", "number", "number"], [p1_m, point1_m2, p3_m]);
        Module.ccall("ge_p1p1_to_p2", "void", ["number", "number"], [p2_m, p1_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [sum_m, p2_m]);
        var res = Module.HEAPU8.subarray(sum_m, sum_m + KEY_SIZE);
        Module._free(point1_m);
        Module._free(point1_m2);
        Module._free(point2_m);
        Module._free(point2_m2);
        Module._free(p2_m);
        Module._free(p1_m);
        Module._free(sum_m);
        Module._free(p3_m);
        return bintohex(res);
    };*/

    this.ge_add = function(p1, p2) {
        if (p1.length !== 64 || p2.length !== 64) {
            throw "ge_add: Invalid p1 or p2 input lengths!";
        }
        return bintohex(nacl.ll.ge_add(hextobin(p1), hextobin(p2)));
    };

    //order matters
    this.ge_sub = function(point1, point2) {
        point2n = ge_neg(point2);
        return ge_add(point1, point2n);
    };

    //adds two scalars together
    this.sc_add = function(scalar1, scalar2) {
        if (scalar1.length !== 64 || scalar2.length !== 64) {
            throw "sc_add: Invalid scalar1 or scalar2 input length!";
        }
        var scalar1_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar2_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.HEAPU8.set(hextobin(scalar1), scalar1_m);
        Module.HEAPU8.set(hextobin(scalar2), scalar2_m);
        var derived_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.ccall("sc_add", "void", ["number", "number", "number"], [derived_m, scalar1_m, scalar2_m]);
        var res = Module.HEAPU8.subarray(derived_m, derived_m + STRUCT_SIZES.EC_SCALAR);
        Module._free(scalar1_m);
        Module._free(scalar2_m);
        Module._free(derived_m);
        return bintohex(res);
    };

    //subtracts one scalar from another
    this.sc_sub = function(scalar1, scalar2) {
        if (scalar1.length !== 64 || scalar2.length !== 64) {
            throw "sc_sub: Invalid scalar1 or scalar2 input lengths!";
        }
        var scalar1_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var scalar2_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.HEAPU8.set(hextobin(scalar1), scalar1_m);
        Module.HEAPU8.set(hextobin(scalar2), scalar2_m);
        var derived_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        Module.ccall("sc_sub", "void", ["number", "number", "number"], [derived_m, scalar1_m, scalar2_m]);
        var res = Module.HEAPU8.subarray(derived_m, derived_m + STRUCT_SIZES.EC_SCALAR);
        Module._free(scalar1_m);
        Module._free(scalar2_m);
        Module._free(derived_m);
        return bintohex(res);
    };

    //fun mul function
    this.sc_mul = function(scalar1, scalar2) {
        if (scalar1.length !== 64 || scalar2.length !== 64) {
            throw "sc_mul: Invalid scalar1 or scalar2 input lengths!";
        }
        return d2s(JSBigInt(s2d(scalar1)).multiply(JSBigInt(s2d(scalar2))).remainder(l).toString());
    };

    //res = c - (ab) mod l; argument names copied from the signature implementation
    this.sc_mulsub = function(sigc, sec, k) {
        if (k.length !== KEY_SIZE * 2 || sigc.length !== KEY_SIZE * 2 || sec.length !== KEY_SIZE * 2 || !this.valid_hex(k) || !this.valid_hex(sigc) || !this.valid_hex(sec)) {
            throw "bad scalar";
        }
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sec), sec_m);
        var sigc_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sigc), sigc_m);
        var k_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(k), k_m);
        var res_m = Module._malloc(KEY_SIZE);

        Module.ccall("sc_mulsub", "void", ["number", "number", "number", "number"], [res_m, sigc_m, sec_m, k_m]);
        res = Module.HEAPU8.subarray(res_m, res_m + KEY_SIZE);
        Module._free(k_m);
        Module._free(sec_m);
        Module._free(sigc_m);
        Module._free(res_m);
        return bintohex(res);
    };

    //res = aB + cG; argument names copied from the signature implementation
    /*this.ge_double_scalarmult_base_vartime = function(sigc, pub, sigr) {
        var pub_m = Module._malloc(KEY_SIZE);
        var pub2_m = Module._malloc(STRUCT_SIZES.GE_P3);
        Module.HEAPU8.set(hextobin(pub), pub_m);
        if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [pub2_m, pub_m]) !== 0) {
            throw "Failed to call ge_frombytes_vartime";
        }
        var sigc_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sigc), sigc_m);
        var sigr_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sigr), sigr_m);
        if (Module.ccall("sc_check", "number", ["number"], [sigc_m]) !== 0 || Module.ccall("sc_check", "number", ["number"], [sigr_m]) !== 0) {
            throw "bad scalar(s)";
        }
        var tmp_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var res_m = Module._malloc(KEY_SIZE);
        Module.ccall("ge_double_scalarmult_base_vartime", "void", ["number", "number", "number", "number"], [tmp_m, sigc_m, pub2_m, sigr_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [res_m, tmp_m]);
        var res = Module. HEAPU8.subarray(res_m, res_m + KEY_SIZE);
        Module._free(pub_m);
        Module._free(pub2_m);
        Module._free(sigc_m);
        Module._free(sigr_m);
        Module._free(tmp_m);
        Module._free(res_m);
        return bintohex(res);
    };*/

    this.ge_double_scalarmult_base_vartime = function(c, P, r) {
        if (c.length !== 64 || P.length !== 64 || r.length !== 64) {
            throw "ge_double_scalarmult_base_vartime: Invalid c, P or r input lengths!";
        }
        return bintohex(nacl.ll.ge_double_scalarmult_base_vartime(hextobin(c), hextobin(P), hextobin(r)));
    };

    //res = a * Hp(B) + c*D
    //res = sigr * Hp(pub) + sigc * k_image; argument names also copied from the signature implementation; note precomp AND hash_to_ec are done internally!!
    /*this.ge_double_scalarmult_postcomp_vartime = function(sigr, pub, sigc, k_image) {
        var image_m = Module._malloc(STRUCT_SIZES.KEY_IMAGE);
        Module.HEAPU8.set(hextobin(k_image), image_m);
        var image_unp_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var image_pre_m = Module._malloc(STRUCT_SIZES.GE_DSMP);
        var tmp3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var sigr_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var sigc_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var tmp2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var res_m = Module._malloc(STRUCT_SIZES.EC_POINT);
        if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [image_unp_m, image_m]) !== 0) {
            throw "Failed to call ge_frombytes_vartime";
        }
        Module.ccall("ge_dsm_precomp", "void", ["number", "number"], [image_pre_m, image_unp_m]);
        var ec = this.hash_to_ec(pub);
        Module.HEAPU8.set(hextobin(ec), tmp3_m);
        Module.HEAPU8.set(hextobin(sigc), sigc_m);
        Module.HEAPU8.set(hextobin(sigr), sigr_m);
        Module.ccall("ge_double_scalarmult_precomp_vartime", "void", ["number", "number", "number", "number", "number"], [tmp2_m, sigr_m, tmp3_m, sigc_m, image_pre_m]);
        Module.ccall("ge_tobytes", "void", ["number", "number"], [res_m, tmp2_m]);
        var res = Module. HEAPU8.subarray(res_m, res_m + STRUCT_SIZES.EC_POINT);
        Module._free(image_m);
        Module._free(image_unp_m);
        Module._free(image_pre_m);
        Module._free(tmp3_m);
        Module._free(sigr_m);
        Module._free(sigc_m);
        Module._free(tmp2_m);
        Module._free(res_m);
        return bintohex(res);
    };*/

    this.ge_double_scalarmult_postcomp_vartime = function(r, P, c, I) {
        if (c.length !== 64 || P.length !== 64 || r.length !== 64 || I.length !== 64) {
            throw "ge_double_scalarmult_postcomp_vartime: Invalid r, p, c or I input lengths!";
        }
        var Pb = this.hash_to_ec_2(P);
        return bintohex(nacl.ll.ge_double_scalarmult_postcomp_vartime(hextobin(r), hextobin(Pb), hextobin(c), hextobin(I)));
    };



    //begin RCT functions

    //xv: vector of secret keys, 1 per ring (nrings)
    //pm: matrix of pubkeys, indexed by size first
    //iv: vector of indexes, 1 per ring (nrings), can be a string
    //size: ring size
    //nrings: number of rings
    //extensible borromean signatures
    this.genBorromean = function(xv, pm, iv, size, nrings){
      if (xv.length !== nrings){
        throw "wrong xv length " + xv.length;
      }
      if (pm.length !== size){
        throw "wrong pm size " + pm.length;
      }
      for (var i = 0; i < pm.length; i++){
        if (pm[i].length !== nrings){
          throw "wrong pm[" + i + "] length " + pm[i].length;
        }
      }
      if (iv.length !== nrings){
        throw "wrong iv length " + iv.length;
      }
      for (var i = 0; i < iv.length; i++){
        if (iv[i] >= size){
          throw "bad indices value at: " + i + ": " + iv[i];
        }
      }
      //signature struct
      var bb = {
        s: [],
        ee: ""
      };
      //signature pubkey matrix
      var L = [];
      //add needed sub vectors (1 per ring size)
      for (var i = 0; i < size; i++){
        bb.s[i] = [];
        L[i] = [];
      }
      //compute starting at the secret index to the last row
      var index;
      var alpha = [];
      for (var i = 0; i < nrings; i++){
        index = parseInt(iv[i]);
        alpha[i] = random_scalar();
        L[index][i] = ge_scalarmult_base(alpha[i]);
        for (var j = index + 1; j < size; j++){
          bb.s[j][i] = random_scalar();
          var c = hash_to_scalar(L[j-1][i]);
          L[j][i] = ge_double_scalarmult_base_vartime(c, pm[j][i], bb.s[j][i]);
        }
      }
      //hash last row to create ee
      var ltemp = "";
      for (var i = 0; i < nrings; i++){
        ltemp += L[size-1][i];
      }
      bb.ee = hash_to_scalar(ltemp);
      //compute the rest from 0 to secret index
      for (var i = 0; i < nrings; i++){
        var cc = bb.ee
        for (var j = 0; j < iv[i]; j++){
          bb.s[j][i] = random_scalar();
          var LL = ge_double_scalarmult_base_vartime(cc, pm[j][i], bb.s[j][i]);
          cc = hash_to_scalar(LL);
        }
        bb.s[j][i] = sc_mulsub(xv[i], cc, alpha[i]);
      }
      return bb;
    };

    //proveRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. http://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or s^i, i=0,...,n
    //   thus this proves that "amount" is in [0, s^n] (we assume s to be 4) (2 for now with v2 txes)
    //   mask is a such that C = aG + bH, and b = amount
    //commitMaskObj = {C: commit, mask: mask}
    this.proveRange = function(commitMaskObj, amount, nrings, enc_seed, exponent){
      var size = 2;
      var C = I; //identity
      var mask = Z; //zero scalar
      var indices = d2b(amount); //base 2 for now
      var sig = {
        Ci: []
        //exp: exponent //doesn't exist for now
      }
      /*payload stuff - ignore for now
      seeds = new Array(3);
      for (var i = 0; i < seeds.length; i++){
        seeds[i] = new Array(1);
      }
      genSeeds(seeds, enc_seed);
      */
      var ai = [];
      var PM = [];
      for (var i = 0; i < size; i++){
        PM[i] = [];
      }
      var j;
      //start at index and fill PM left and right -- PM[0] holds Ci
      for (i = 0; i < nrings; i++){
        ai[i] = random_scalar();
        j = indices[i];
        PM[j][i] = ge_scalarmult_base(ai[i]);
        while (j > 0){
          j--;
          PM[j][i] = ge_add(PM[j+1][i], H2[i]); //will need to use i*2 for base 4 (or different object)
        }
        j = indices[i];
        while (j < size - 1){
          j++;
          PM[j][i] = ge_sub(PM[j-1][i], H2[i]); //will need to use i*2 for base 4 (or different object)
        }
        mask = sc_add(mask, ai[i]);
      }
      /*
      * some more payload stuff here
      */
      //copy commitments to sig and sum them to commitment
      for (i = 0; i < nrings; i++){
        //if (i < nrings - 1) //for later version
        sig.Ci[i] = PM[0][i];
        C = ge_add(C, PM[0][i]);
      }
      /* exponent stuff - ignore for now
      if (exponent){
        n = JSBigInt(10);
        n = n.pow(exponent).toString();
        mask = sc_mul(mask, d2s(n)); //new sum
      }
      */
      sig.bsig = this.genBorromean(ai, PM, indices, size, nrings);
      commitMaskObj.C = C;
      commitMaskObj.mask = mask;
      return sig;
    };


    function array_hash_to_scalar(array){
      var buf = ""
      for (var i = 0; i < array.length; i++){
        if (typeof array[i] !== "string"){throw "unexpected array element";}
        buf += array[i];
      }
      return hash_to_scalar(buf);
    }

    // Gen creates a signature which proves that for some column in the keymatrix "pk"
    //   the signer knows a secret key for each row in that column
    // we presently only support matrices of 2 rows (pubkey, commitment)
    // this is a simplied MLSAG_Gen function to reflect that
    // because we don't want to force same secret column for all inputs
    this.MLSAG_Gen = function(message, pk, xx, kimg, index){
      var cols = pk.length; //ring size
      if (index >= cols){throw "index out of range";}
      var rows = pk[0].length; //number of signature rows (always 2)
      if (rows !== 2){throw "wrong row count";}
      for (var i = 0; i < cols; i++){
        if (pk[i].length !== rows){throw "pk is not rectangular";}
      }
      if (xx.length !== rows){throw "bad xx size";}

      var c_old = "";
      var alpha = [];

      var rv = {
        ss: [],
        cc: null
      };
      for (i = 0; i < cols; i++){
        rv.ss[i] = [];
      }
      var toHash = []; //holds 6 elements: message, pubkey, dsRow L, dsRow R, commitment, ndsRow L
      toHash[0] = message;

      //secret index (pubkey section)
      alpha[0] = random_scalar(); //need to save alphas for later
      toHash[1] = pk[index][0]; //secret index pubkey
      toHash[2] = ge_scalarmult_base(alpha[0]); //dsRow L
      toHash[3] = generate_key_image_2(pk[index][0], alpha[0]); //dsRow R (key image check)
      //secret index (commitment section)
      alpha[1] = random_scalar();
      toHash[4] = pk[index][1]; //secret index commitment
      toHash[5] = ge_scalarmult_base(alpha[1]); //ndsRow L

      c_old = array_hash_to_scalar(toHash);

      i = (index + 1) % cols;
      if (i === 0){
        rv.cc = c_old;
      }
      while (i != index){
        rv.ss[i][0] = random_scalar(); //dsRow ss
        rv.ss[i][1] = random_scalar(); //ndsRow ss

        //!secret index (pubkey section)
        toHash[1] = pk[i][0];
        toHash[2] = ge_double_scalarmult_base_vartime(c_old, pk[i][0], rv.ss[i][0]);
        toHash[3] = ge_double_scalarmult_postcomp_vartime(rv.ss[i][0], pk[i][0], c_old, kimg);
        //!secret index (commitment section)
        toHash[4] = pk[i][1];
        toHash[5] = ge_double_scalarmult_base_vartime(c_old, pk[i][1], rv.ss[i][1]);
        c_old = array_hash_to_scalar(toHash); //hash to get next column c
        i = (i + 1) % cols;
        if (i === 0){
          rv.cc = c_old;
        }
      }
      for (i = 0; i < rows; i++){
        rv.ss[index][i] = sc_mulsub(c_old, xx[i], alpha[i]);
      }
      return rv;
    };

    //prepares for MLSAG_Gen
    this.proveRctMG = function(message, pubs, inSk, kimg, mask, Cout, index){
      var cols = pubs.length;
      if (cols < 3){throw "cols must be > 2 (mixin)";}
      var xx = [];
      var PK = [];
      //fill pubkey matrix (copy destination, subtract commitments)
      for (var i = 0; i < cols; i++){
        PK[i] = [];
        PK[i][0] = pubs[i].dest;
        PK[i][1] = ge_sub(pubs[i].mask, Cout);
      }
      xx[0] = inSk.x;
      xx[1] = sc_sub(inSk.a, mask);
      return this.MLSAG_Gen(message, PK, xx, kimg, index);
    };

    this.get_pre_mlsag_hash = function(rv) {
        var hashes = "";
        hashes += rv.message;
        hashes += this.cn_fast_hash(this.serialize_rct_base(rv));
        var buf = serialize_range_proofs(rv);
        hashes += this.cn_fast_hash(buf);
        return this.cn_fast_hash(hashes);
    }

    function serialize_range_proofs(rv, fortx) {
        var buf = "";
        if (rv.type !== 5) {
            for (var i = 0; i < rv.p.rangeSigs.length; i++) {
                for (var j = 0; j < rv.p.rangeSigs[i].bsig.s.length; j++) {
                    for (var l = 0; l < rv.p.rangeSigs[i].bsig.s[j].length; l++) {
                        buf += rv.p.rangeSigs[i].bsig.s[j][l];
                    }
                }
                buf += rv.p.rangeSigs[i].bsig.ee;
                for (j = 0; j < rv.p.rangeSigs[i].Ci.length; j++) {
                    buf += rv.p.rangeSigs[i].Ci[j];
                }
            }
        } else {
            if (fortx) {buf += "01000000";} //#bulletproofs, uint32
            buf += rv.p.bp[0].A;
            buf += rv.p.bp[0].S;
            buf += rv.p.bp[0].T1;
            buf += rv.p.bp[0].T2;
            buf += rv.p.bp[0].taux;
            buf += rv.p.bp[0].mu;
            if (fortx) {buf += this.encode_varint(rv.p.bp[0].L.length);}
            for (var i = 0; i < rv.p.bp[0].L.length; i++) {
                buf += rv.p.bp[0].L[i];
            }
            if (fortx) {buf += this.encode_varint(rv.p.bp[0].R.length);}
            for (i = 0; i < rv.p.bp[0].R.length; i++) {
                buf += rv.p.bp[0].R[i];
            }
            buf += rv.p.bp[0].a;
            buf += rv.p.bp[0].b;
            buf += rv.p.bp[0].t;
        }
        return buf;
    }

    this.ge_add_raw = function(A, B) {
        if (B.length === 64) {
            B = nacl.ll.unpack(hextobin(B));
        }
        if (A.length === 64) {
            A = nacl.ll.unpack(hextobin(A));
        }
        nacl.ll.ge_add_raw(A, B);
        return A; //in case of hex input
    };

    this.sc_muladd = function(a, b, c) {
        if (a.length !== KEY_SIZE * 2 || b.length !== KEY_SIZE * 2 || c.length !== KEY_SIZE * 2 || !this.valid_hex(a) || !this.valid_hex(b) || !this.valid_hex(c)) {
            throw "bad scalar";
        }
        return swapEndian(("0000000000000000000000000000000000000000000000000000000000000000" + (JSBigInt.parse(swapEndian(a), 16).multiply(JSBigInt.parse(swapEndian(b), 16)).add(JSBigInt.parse(swapEndian(c), 16)).remainder(l).toString(16))).toLowerCase().slice(-64));
        //return d2s(JSBigInt(s2d(a)).multiply(JSBigInt(s2d(b))).add(JSBigInt(s2d(c))).remainder(l).toString());
    };

    this.ge_double_scalarmult_postcomp_vartime_2 = function(a, A, b, B) {
        if (a.length !== 64 || A.length !== 64 || b.length !== 64 || B.length !== 64) {
            throw "Invalid input length!";
        }
        return bintohex(nacl.ll.ge_double_scalarmult_postcomp_vartime(hextobin(a), hextobin(A), hextobin(b), hextobin(B)));
    };

     this.ge_double_scalarmult_postcomp_vartime_2_raw_output = function(a, A, b, B) {
        if (a.length !== 64 || A.length !== 64 || b.length !== 64 || B.length !== 64) {
            throw "Invalid input length!";
        }
        return nacl.ll.ge_double_scalarmult_postcomp_vartime_raw_output(hextobin(a), hextobin(A), hextobin(b), hextobin(B));
    };

    this.ge_scalarmult_raw = function(A, a) {
        if (A.length === 64) {
            A = nacl.ll.unpack(hextobin(A));
        }
        return nacl.ll.ge_scalarmult_raw(A, hextobin(a));
    };

    //message is normal prefix hash
    //inSk is vector of x,a
    //kimg is vector of kimg
    //destinations is vector of pubkeys (we skip and proxy outAmounts instead)
    //inAmounts is vector of strings
    //outAmounts is vector of strings
    //mixRing is matrix of pubkey, commit (dest, mask)
    //amountKeys is vector of scalars
    //indices is vector
    //txnFee is string
    this.genRct = function(message, inSk, kimg, /*destinations, */inAmounts, outAmounts, mixRing, amountKeys, indices, txnFee){
      if (outAmounts.length !== amountKeys.length ){throw "different number of amounts/amount_keys";}
      for (var i = 0; i < mixRing.length; i++){
        if (mixRing[i].length <= indices[i]){throw "bad mixRing/index size";}
      }
      if (mixRing.length !== inSk.length){throw "mismatched mixRing/inSk";}
      if (inAmounts.length !== inSk.length){throw "mismatched inAmounts/inSk";}
      if (indices.length !== inSk.length){throw "mismatched indices/inSk";}

      rv = {
        type: RCTTypeBulletproof,
        message: message,
        outPk: [],
        p: {
          rangeSigs: [],
          bp: [],
          MGs: [],
          pseudoOuts: []
        },
        ecdhInfo: [],
        txnFee: txnFee.toString(),
        pseudoOuts: []
      };

      var sumout = Z;
      if (rv.type !== 5) {//borromean
        var cmObj = {
          C: null,
          mask: null
        };
        var nrings = 64; //for base 2/current
        //compute range proofs, etc
        for (i = 0; i < outAmounts.length; i++){
          var teststart = new Date().getTime();
          rv.p.rangeSigs[i] = this.proveRange(cmObj, outAmounts[i], nrings, 0, 0);
          var testfinish = new Date().getTime() - teststart;
          //console.log("Time take for range proof " + i + ": " + testfinish);
          rv.outPk[i] = cmObj.C;
          sumout = this.sc_add(sumout, cmObj.mask);
          rv.ecdhInfo[i] = this.encode_rct_ecdh({mask: cmObj.mask, amount: d2s(outAmounts[i])}, amountKeys[i]);
        }
      } else {//bulletproofs
        //bulletproof stuff
        var svs = [], gamma = [];
        for (i = 0; i < outAmounts.length; i++) {
          svs[i] = outAmounts[i];
          gamma[i] = this.random_scalar();
          sumout = this.sc_add(sumout, gamma[i]);
          rv.ecdhInfo[i] = this.encode_rct_ecdh({mask: gamma[i], amount: d2s(outAmounts[i])}, amountKeys[i]);
        }
        rv.p.bp.push(this.bulletproof_PROVE(svs, gamma));
        for (i = 0; i < outAmounts.length; i++) {
          rv.outPk[i] = this.ge_scalarmult(rv.p.bp[0].V[i], d2s("8"));
        }
      }

      //simple (1 input) OR bulletproof is always simple
      if (rv.type !== 1 && rv.type !== 3){
        var ai = [];
        var sumpouts = Z;
        //create pseudoOuts
        for (i = 0; i < inAmounts.length - 1; i++){
          ai[i] = random_scalar();
          sumpouts = sc_add(sumpouts, ai[i]);
          if (rv.type === 2 || rv.type === 4) {
            rv.pseudoOuts[i] = commit(d2s(inAmounts[i]), ai[i]);
          } else {//pseudoOuts moved to prunable with bulletproofs
            rv.p.pseudoOuts[i] = commit(d2s(inAmounts[i]), ai[i]);
          }
        }
        ai[i] = sc_sub(sumout, sumpouts);
        if (rv.type === 2 || rv.type === 4) {
          rv.pseudoOuts[i] = commit(d2s(inAmounts[i]), ai[i]);
        } else {//pseudoOuts moved to prunable with bulletproofs
          rv.p.pseudoOuts[i] = commit(d2s(inAmounts[i]), ai[i]);
        }
        //console.log(rv);
        var full_message = this.get_pre_mlsag_hash(rv);
        for (i = 0; i < inAmounts.length; i++){
          rv.p.MGs.push(this.proveRctMG(full_message, mixRing[i], inSk[i], kimg[i], ai[i], (rv.type === 2 || rv.type === 4 ? rv.pseudoOuts[i] : rv.p.pseudoOuts[i]), indices[i]));
        }
      } else {
        var sumC = I;
        //get sum of output commitments to use in MLSAG
        for (i = 0; i < rv.outPk.length; i++){
          sumC = ge_add(sumC, rv.outPk[i]);
        }
        sumC = ge_add(sumC, ge_scalarmult(H, d2s(rv.txnFee)));
        var full_message = this.get_pre_mlsag_hash(rv);
        rv.p.MGs.push(this.proveRctMG(full_message, mixRing[0], inSk[0], kimg[0], sumout, sumC, indices[0]));
      }
      return rv;
    };

    //end RCT functions


    this.add_pub_key_to_extra = function(extra, pubkey) {
        if (pubkey.length !== 64) throw "Invalid pubkey length";
        // Append pubkey tag and pubkey
        extra += TX_EXTRA_TAGS.PUBKEY + pubkey;
        return extra;
    };

    this.add_nonce_to_extra = function(extra, nonce) {
        // Append extra nonce
        if ((nonce.length % 2) !== 0) {
            throw "Invalid extra nonce";
        }
        if ((nonce.length / 2) > TX_EXTRA_NONCE_MAX_COUNT) {
            throw "Extra nonce must be at most " + TX_EXTRA_NONCE_MAX_COUNT + " bytes";
        }
        // Add nonce tag
        extra += TX_EXTRA_TAGS.NONCE;
        // Encode length of nonce
        extra += ('0' + (nonce.length / 2).toString(16)).slice(-2);
        // Write nonce
        extra += nonce;
        return extra;
    };

    this.get_payment_id_nonce = function(payment_id, pid_encrypt) {
        if (payment_id.length !== 64 && payment_id.length !== 16) {
            throw "Invalid payment id";
        }
        var res = '';
        if (pid_encrypt) {
            res += TX_EXTRA_NONCE_TAGS.ENCRYPTED_PAYMENT_ID;
        } else {
            res += TX_EXTRA_NONCE_TAGS.PAYMENT_ID;
        }
        res += payment_id;
        return res;
    };

    this.abs_to_rel_offsets = function(offsets) {
        if (offsets.length === 0) return offsets;
        for (var i = offsets.length - 1; i >= 1; --i) {
            offsets[i] = new JSBigInt(offsets[i]).subtract(offsets[i - 1]).toString();
        }
        return offsets;
    };

    this.get_tx_prefix_hash = function(tx) {
        var prefix = this.serialize_tx(tx, true);
        return this.cn_fast_hash(prefix);
    };

    this.get_tx_hash = function(tx) {
        if (typeof(tx) === 'string') {
            return this.cn_fast_hash(tx);
        } else {
            return this.cn_fast_hash(this.serialize_tx(tx));
        }
    };

    this.serialize_tx = function(tx, headeronly) {
        //tx: {
        //  version: uint64,
        //  unlock_time: uint64,
        //  extra: hex,
        //  vin: [{amount: uint64, k_image: hex, key_offsets: [uint64,..]},...],
        //  vout: [{amount: uint64, target: {key: hex}},...],
        //  signatures: [[s,s,...],...]
        //}
        if (headeronly === undefined) {
            headeronly = false;
        }
        var buf = "";
        buf += this.encode_varint(tx.version);
        buf += this.encode_varint(tx.unlock_time);
        buf += this.encode_varint(tx.vin.length);
        var i, j;
        for (i = 0; i < tx.vin.length; i++) {
            var vin = tx.vin[i];
            switch (vin.type) {
                case "input_to_key":
                    buf += "02";
                    buf += this.encode_varint(vin.amount);
                    buf += this.encode_varint(vin.key_offsets.length);
                    for (j = 0; j < vin.key_offsets.length; j++) {
                        buf += this.encode_varint(vin.key_offsets[j]);
                    }
                    buf += vin.k_image;
                    break;
                default:
                    throw "Unhandled vin type: " + vin.type;
            }
        }
        buf += this.encode_varint(tx.vout.length);
        for (i = 0; i < tx.vout.length; i++) {
            var vout = tx.vout[i];
            buf += this.encode_varint(vout.amount);
            switch (vout.target.type) {
                case "txout_to_key":
                    buf += "02";
                    buf += vout.target.key;
                    break;
                default:
                    throw "Unhandled txout target type: " + vout.target.type;
            }
        }
        if (!this.valid_hex(tx.extra)) {
            throw "Tx extra has invalid hex";
        }
        buf += this.encode_varint(tx.extra.length / 2);
        buf += tx.extra;
        if (!headeronly) {
            if (tx.vin.length !== tx.signatures.length) {
                throw "Signatures length != vin length";
            }
            for (i = 0; i < tx.vin.length; i++) {
                for (j = 0; j < tx.signatures[i].length; j++) {
                    buf += tx.signatures[i][j];
                }
            }
        }
        return buf;
    };

    this.serialize_rct_tx_with_hash = function(tx) {
        var hashes = "";
        var buf = "";
        buf += this.serialize_tx(tx, true);
        hashes += this.cn_fast_hash(buf);
        var buf2 = this.serialize_rct_base(tx.rct_signatures);
        hashes += this.cn_fast_hash(buf2);
        buf += buf2;
        var buf3 = serialize_range_proofs(tx.rct_signatures, true);
        //add MGs
        for (var i = 0; i < tx.rct_signatures.p.MGs.length; i++) {
            for (var j = 0; j < tx.rct_signatures.p.MGs[i].ss.length; j++) {
                buf3 += tx.rct_signatures.p.MGs[i].ss[j][0];
                buf3 += tx.rct_signatures.p.MGs[i].ss[j][1];
            }
            buf3 += tx.rct_signatures.p.MGs[i].cc;
        }
        if (tx.rct_signatures.type === 5) {
            for (var i = 0; i < tx.rct_signatures.p.pseudoOuts.length; i++) {
                buf3 += tx.rct_signatures.p.pseudoOuts[i];
            }
        }
        hashes += this.cn_fast_hash(buf3);
        buf += buf3;
        var hash = this.cn_fast_hash(hashes);
        return {
            raw: buf,
            hash: hash,
            prvkey: tx.prvkey
        };
    };

    this.serialize_rct_base = function(rv) {
        var buf = "";
        buf += this.encode_varint(rv.type);
        buf += this.encode_varint(rv.txnFee);
        if (rv.type === 2) {
            for (var i = 0; i < rv.pseudoOuts.length; i++) {
                buf += rv.pseudoOuts[i];
            }
        }
        if (rv.ecdhInfo.length !== rv.outPk.length) {
            throw "mismatched outPk/ecdhInfo!";
        }
        for (i = 0; i < rv.ecdhInfo.length; i++) {
            buf += rv.ecdhInfo[i].mask;
            buf += rv.ecdhInfo[i].amount;
        }
        for (i = 0; i < rv.outPk.length; i++) {
            buf += rv.outPk[i];
        }
        return buf;
    };

    this.generate_ring_signature = function(prefix_hash, k_image, keys, sec, real_index) {
        if (k_image.length !== STRUCT_SIZES.KEY_IMAGE * 2) {
            throw "invalid key image length";
        }
        if (sec.length !== KEY_SIZE * 2) {
            throw "Invalid secret key length";
        }
        if (prefix_hash.length !== HASH_SIZE * 2 || !this.valid_hex(prefix_hash)) {
            throw "Invalid prefix hash";
        }
        if (real_index >= keys.length || real_index < 0) {
            throw "real_index is invalid";
        }
        var _ge_tobytes = Module.cwrap("ge_tobytes", "void", ["number", "number"]);
        var _ge_p3_tobytes = Module.cwrap("ge_p3_tobytes", "void", ["number", "number"]);
        var _ge_scalarmult_base = Module.cwrap("ge_scalarmult_base", "void", ["number", "number"]);
        var _ge_scalarmult = Module.cwrap("ge_scalarmult", "void", ["number", "number", "number"]);
        var _sc_add = Module.cwrap("sc_add", "void", ["number", "number", "number"]);
        var _sc_sub = Module.cwrap("sc_sub", "void", ["number", "number", "number"]);
        var _sc_mulsub = Module.cwrap("sc_mulsub", "void", ["number", "number", "number", "number"]);
        var _sc_0 = Module.cwrap("sc_0", "void", ["number"]);
        var _ge_double_scalarmult_base_vartime = Module.cwrap("ge_double_scalarmult_base_vartime", "void", ["number", "number", "number", "number"]);
        var _ge_double_scalarmult_precomp_vartime = Module.cwrap("ge_double_scalarmult_precomp_vartime", "void", ["number", "number", "number", "number", "number"]);
        var _ge_frombytes_vartime = Module.cwrap("ge_frombytes_vartime", "number", ["number", "number"]);
        var _ge_dsm_precomp = Module.cwrap("ge_dsm_precomp", "void", ["number", "number"]);

        var buf_size = STRUCT_SIZES.EC_POINT * 2 * keys.length;
        var buf_m = Module._malloc(buf_size);
        var sig_size = STRUCT_SIZES.SIGNATURE * keys.length;
        var sig_m = Module._malloc(sig_size);

        // Struct pointer helper functions
        function buf_a(i) {
            return buf_m + STRUCT_SIZES.EC_POINT * (2 * i);
        }
        function buf_b(i) {
            return buf_m + STRUCT_SIZES.EC_POINT * (2 * i + 1);
        }
        function sig_c(i) {
            return sig_m + STRUCT_SIZES.EC_SCALAR * (2 * i);
        }
        function sig_r(i) {
            return sig_m + STRUCT_SIZES.EC_SCALAR * (2 * i + 1);
        }
        var image_m = Module._malloc(STRUCT_SIZES.KEY_IMAGE);
        Module.HEAPU8.set(hextobin(k_image), image_m);
        var i;
        var image_unp_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var image_pre_m = Module._malloc(STRUCT_SIZES.GE_DSMP);
        var sum_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var k_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var h_m = Module._malloc(STRUCT_SIZES.EC_SCALAR);
        var tmp2_m = Module._malloc(STRUCT_SIZES.GE_P2);
        var tmp3_m = Module._malloc(STRUCT_SIZES.GE_P3);
        var pub_m = Module._malloc(KEY_SIZE);
        var sec_m = Module._malloc(KEY_SIZE);
        Module.HEAPU8.set(hextobin(sec), sec_m);
        if (_ge_frombytes_vartime(image_unp_m, image_m) != 0) {
            throw "failed to call ge_frombytes_vartime";
        }
        _ge_dsm_precomp(image_pre_m, image_unp_m);
        _sc_0(sum_m);
        for (i = 0; i < keys.length; i++) {
            if (i === real_index) {
                // Real key
                var rand = this.random_scalar();
                Module.HEAPU8.set(hextobin(rand), k_m);
                _ge_scalarmult_base(tmp3_m, k_m);
                _ge_p3_tobytes(buf_a(i), tmp3_m);
                var ec = this.hash_to_ec(keys[i]);
                Module.HEAPU8.set(hextobin(ec), tmp3_m);
                _ge_scalarmult(tmp2_m, k_m, tmp3_m);
                _ge_tobytes(buf_b(i), tmp2_m);
            } else {
                Module.HEAPU8.set(hextobin(this.random_scalar()), sig_c(i));
                Module.HEAPU8.set(hextobin(this.random_scalar()), sig_r(i));
                Module.HEAPU8.set(hextobin(keys[i]), pub_m);
                if (Module.ccall("ge_frombytes_vartime", "void", ["number", "number"], [tmp3_m, pub_m]) !== 0) {
                    throw "Failed to call ge_frombytes_vartime";
                }
                _ge_double_scalarmult_base_vartime(tmp2_m, sig_c(i), tmp3_m, sig_r(i));
                _ge_tobytes(buf_a(i), tmp2_m);
                var ec = this.hash_to_ec(keys[i]);
                Module.HEAPU8.set(hextobin(ec), tmp3_m);
                _ge_double_scalarmult_precomp_vartime(tmp2_m, sig_r(i), tmp3_m, sig_c(i), image_pre_m);
                _ge_tobytes(buf_b(i), tmp2_m);
                _sc_add(sum_m, sum_m, sig_c(i));
            }
        }
        var buf_bin = Module.HEAPU8.subarray(buf_m, buf_m + buf_size);
        var scalar = this.hash_to_scalar(prefix_hash + bintohex(buf_bin));
        Module.HEAPU8.set(hextobin(scalar), h_m);
        _sc_sub(sig_c(real_index), h_m, sum_m);
        _sc_mulsub(sig_r(real_index), sig_c(real_index), sec_m, k_m);
        var sig_data = bintohex(Module.HEAPU8.subarray(sig_m, sig_m + sig_size));
        var sigs = [];
        for (var k = 0; k < keys.length; k++) {
            sigs.push(sig_data.slice(STRUCT_SIZES.SIGNATURE * 2 * k, STRUCT_SIZES.SIGNATURE * 2 * (k + 1)));
        }
        Module._free(image_m);
        Module._free(image_unp_m);
        Module._free(image_pre_m);
        Module._free(sum_m);
        Module._free(k_m);
        Module._free(h_m);
        Module._free(tmp2_m);
        Module._free(tmp3_m);
        Module._free(buf_m);
        Module._free(sig_m);
        Module._free(pub_m);
        Module._free(sec_m);
        return sigs;
    };

    //*******************************************
    //********Begin Bulletproof functions********
    //*******************************************

    this.get_exponent = function(base, index) {
        var salt = "62756c6c657470726f6f66"; //"bulletproof"
        var hashed = base + salt + this.encode_varint(index);
        //console.log("1");
        return this.hash_to_ec_2(cn_fast_hash(hashed)); //no way this works -- it works
    };

    //create the new bases -- cached below
    this.init_exponents = function() {
        var teststart = new Date().getTime();
        for (var i = 0; i < maxN*2; i++) { //MyMonero can only send to 2 destinations as of now; don't create more than we need
            Hi[i] = this.get_exponent(H, i*2);
            Gi[i] = this.get_exponent(H, i*2+1);
        }
        var testfinish = new Date().getTime() - teststart;
    };

    //cache exponents
    Hi = [
    "42ba668a007d0fcd6fea4009de8a6437248f2d445230af004a89fd04279bc297", "e5224ef871eeb87211511d2a5cb81eeaa160a8a5408eab5deaeb9d4558780947", "8fc547c0c52e90e01ecd2ce41bfc624086f0ecdc260cf30e1b9cae3b18ed6b2c", "9f11044145da98e3111b40a1078ea90457b28b01462c90e3d847949ed8c1d31d",
    "179637ec7565f76fa20acc471b1694b795ca44618e4cc68e0a46b20f91e86777", "251dad91f0d5d451d7e94bfcd413934c1da173a92ddc0d5e0e4c2cfbe5925b0b", "889c8022f3a7e42fcfd4eacd06316315c8c06cb667176e8fd675e18a2296100a", "d34206fcf444357be1e9872f59d71c4e66afdf7c196b6a596be2890c0aea928a",
    "9c69d2c4df3b9c528bce2c0c306b6291dea28de1c023328719e9a1ba1d849c1b", "b446bc0b0d3776250dd66d9727c25d0efeb0f931fc537ab2bd9f8978216f6eb6", "e423fae0d374d34a20694e397a70b84b75e3be14b2cf5301c7cbc662509671a5", "e593736f6113c3f288ec00a1cc2fc7156f4fffa1748e9b2c2ddf2f4303bbfe7f",
    "fcee5e57b3b84206a91bcf32f712c75e5fa5108785b8cc2447998312ca31ab85", "00c82c62684539a27001fb17f2a5649db2e2d64b6b88f0d681009ae78eaece9c", "7357802c6c1cd81ef6248689854089aad694473391bad618ef01dfd680981a78", "9718e9d7caef063deb2d675fe843ea634dcf9677c1d3ee92513971b724c788e4",
    "107a4240fe26e5fb36cc007e7658964882f769f18c786ab152f25c5d2ae472f7", "1e4013c4b0c5787dc1d78bdc8d52331039af4124112ee9346f110a4e8118e864", "115d49b082c83851d4d5e110a4abdaddbda9b0227f5b26bf52d5a22525235972", "843de91d99d0091f17f4782d4feb2b760cd58b6f2476e8b02d908a1515078aa8",
    "08aa3a565efcb7169fe0cbf72c12ce1750f2861fb6c6851613cbe974efc1684a", "ebbe8b8a522abbe78277d0daa7892d9da87c27becd3ec03895233ad466318c44", "3c4d6d5cf12eba7dbd3e84329df61afc9b7e08fc1332a682344273396ec7dcdc", "beae48ff70a19a31d662443cce57f77afe050b81224860255bcbc8f480c43cfd",
    "ebb1b2a68972b7d3323b0361f3a1142f8b452e9298773def5635c2e2efa3700e", "4cc9e5d8de78967e573582cf7c74977c30b5469b2c0bace8ec259f71ba25c8dd", "1c51e5b0241cca7c86f718b7d2c3d457a6e5e0b39f1f39ebafbb0883d427d936", "476015ad88b792a031e4dd983757c99aea3912e8f8c2f659de4bc1a2204cea13",
    "2e4f9ef71777119153639a71ff2417f522fe41b87e9c1cb7669f40f9d685887d", "ff81927aa42eda7f2a696789091033cf5be2fc1f5f3a2de22715eb33d6282892", "2dac862efc7fc6d54c99e6ec6e58c0b64da957e736d30093c867a120d5dbfc55", "03ca276405df4b2dbe6cfe7c2c56bcd2669f1b7d82c9f92991bf4102af6110bf",
    "1bf5bdae897f9a064209cf31299653137e865f905c8929449139545ac8253c32", "be19cc8bd854ca7cdb07c2aeba12a14ccfa3085f9ffd9f753980c9d45b7b4e0f", "5be46df3ae5c10c189f1dc9ed2592e246bd2449aa0daae458ae8bfbd52f983c3", "de44123726719c08d4c37c8c9b0be17b6b49826136aa7b908531bc91732b087a",
    "4136030bad7b5b1cfa7d9c98a9dc347a92651f29c2e110aff8897f267c042210", "a6b70a313cc06afa2bd9c2911537d609d68bec9432e84b9679527d6abb588ba7", "2bb214987069d80b0abc2bbd68eba0331e3ae5f4106f7fc1e2e7b8d6e5370e32", "01cce2a036b68ed354316339f092dec7662bcebdd2066111d16ce55a937e2c61",
    "907bc366c885daa37495be671ef6c2f2e554ede3b53ce280cbe88a48b9d9740e", "980ceaf804edcd8c96858193e6d5178bf604cc73bd8faad50d531549993197cc", "272827216d1af9dcc6e9862a6e53a0a2c73298e1fadc0f9148cbc85ec0567c38", "769c2765d654c4269f6ef13947f13c239cbb08b7cf67a25bac030ad1b892c434",
    "79246449f5328dac3141d3d7c8a9a2540dcac2cbc98e27843143e7d4b96dde75", "21fc70b3280a2a4c5f39287f5d24d7a759ea037b11448739ee2a28fc4b160eac", "406108aee6b580621311fe030bf08b4f6eed3d7d3d8693d3ac524da2b4ebf19e", "2559dc50ff35e62da620dc0a02edcbe4f398b1bd86ea154b6a9400579e3f1cd5",
    "7fdc2f10bd8cdb167c0b283f9007e620d9ca28067fe2b015ed657c9153b8443d", "77e8e25ff348f4df78bbc1ce20a7babde40ed2bdbeaf2b5cd98e5202baf7e3dc", "f18ba115620c51ae8b58b4923b9a8694c93df64b178c4cd2f9f6efc51f458b0c", "5ee860a40ac8cec3506ec85b99dc716b95cbb342db91ade4b61e177f60f9fabb",
    "ff2c9badee04cfd741d66d2f26321e2cf50a3cd021f6288863de2dadf8d52d1f", "8b9f51424305a3d407962963c1d0beeb8113f80307ecc21923947fe8cbaf5c2c", "05ae6369852199c52a1797b9aff2a9245d7a8b9172d572b4432f63441ff51c4a", "4e270e3b61eae6e13eefe35e85427bc758ef4af4c00f9c77521c0361d299431f",
    "9d8e298c13414c46170a1d82a1380fbafe531ca70184ab8965c4c807060e8039", "fec4615e5909d27ac5ca8041e3f95b27f1c3d4d406a2048b1e6ce1e637cb87c0", "f97d3617d46aeffdd1e813c255fb8b3ef939a2c5fad4d10973c08c055f7913c5", "1664589da5145a9c5972f4b212ebf51171d92343833a08953cd80cd0d908904c",
    "563edc34294221865633d8cf6ff50444b9d29beb05a47b8bb121cb118d6cb16b", "24c445098aa90e6d5a10eae0a0f3977a2808f79cafe8f8705297bd91ebbf2792", "a1892cb009db0b7ac351d0353f43fe3aa97192e8b9d7fef5baec415b0ca48c92", "0e7cdd78f9246ad254e87ee1b06584b860b0b8800aaee17896f0290cb789b0d7",
    "9ecd7d04cdeda710efa55e76e4731485ba1ff86a31faadfaf5628fbf1711346d", "573254ba0f56b538f75b6fc4321745ed42a319a8efb868a6f35a64a6c744a696", "c91a61125fad2592020256fa8a6141a74b9d4962deec53ab7514ca3aceded524", "997a9aeb7c430fbf01d936fdc76f55eecb74963248dfb4a15f71f7a93035143c",
    "8f42e31aed71bdecd9535424e77d3148491ff7e463f638a62dad5695ef934e96", "fd5e21304ace05c42af986607781ab5766c18383071fe35f16a589d4e481a932", "217c3bc5628d67293f50bffe46988ee10c3e30586c77451ba75808464dc1ac64", "502e8fde87b5d3c8977ee90d637d4b2db92aced20cdcaf5da0ad154adc682dd7",
    "2f0f33bcf6bdcce6fe178c82ca183dce8c8237f9f58f84b4b108f79785710831", "1766840297cacb0d7d2a28b447555f39a1da0dda875e9d06e0a48e2b637a8fd3", "6f34e56e3028deeb3636c14f5387cc832beee7add41d8abd1f6a503dbf2ef9ca", "55e5db159a024fb46fa89c00322330a0eec9d8673a8cf5600db477acaed4afa2",
    "4113429e2124da8107dae9467c5f976eb01d36ad575ee4486ebd2ca6b0d934e1", "f4cd6ecc0f0f10a54443880315ceb97fcd3fa2093dbeabefe5d49be67eca9f4a", "f02f64a813c3a375be1150a28c4527ff675dc076f44ce19c6fa28106b797c9c0", "cb32c590f76caaa951a6709dc37526ccc3061653943d4b4fc61ac6022a63de69",
    "5ad23d9526629a6bf6ff3382d4be95491127531bb69ea3699cac5f21fe652e10", "8eccd05d9a10c0423f722f971c841d0fe02a82ce3f65ca23d0dede39264bf27f", "9c70526636fa493ebce06ed2905beb2d6632e8097cc1c46a487933f46330a048", "582021b0ab0c6df24c547b99e98a19fecd8d1867d999f4f59d7bca1913b2cf74",
    "6dd3bea6ec65b1edc20cde46ad02cf555997f0b188c0eb02ab4c8aff11c202c1", "9f1607cf2e8d64a7bf6f21c24f1eb125bcc6264a35b78172e4f9d34b120a36f2", "549f6baca4568520b57ae0d0b1ce5d3b2b7932b8110faecdabb36455eb5ad3ec", "875d1634f6c5b6b9a5b0d3a0326a79c03408b818e730e19c22e9fbda0ad0eeb7",
    "85198e18ad6e98e444bdd5deda8ce90ba9e8fd276f4e135ae5b2751ec40bf35d", "b6c3d275338bb959a0750de700b074abc41b126c690caeed54a296d90122dcf4", "8a7a81e13f401b7a585268586839f7ca166a46f2989b72258dc828c23d40af74", "9b4db945d3fae8833ccf22e5f4c3a2e9abf227dc004c1fc5e496976557edd709",
    "d41a7ed6af6be48d7ede5e8e6de31d2fe812d777eb0d59a6e9155220b20dd8d4", "3aa3af5099493b25fba1337d4e79ec2c10b48fadbb4c93b932e806cb49d9fa17", "b1d86317c098032e164663c4669acbeeb43845dd2ded341a5f056b8a2b7102fe", "c18caf2504bc37c0d4c9b38f1bf362381e13a5a3939ae306e821620d07a90088",
    "01e969ad4086c111a6a1fbd229b8fd0609cfd08a019c0f46382a7a9189e2968f", "0012b70fc773451ced065c0f8048171c0f5dfc965b2260530fb050475b00ea42", "cf37f0d428e01e761f1729294f070eaa8e155e2ea0d96c9654818a6e5f1523ac", "3bd87bf25634861d6a9e286a3fa3fb26afb4e5544585319cf02308730716915e",
    "70b367b2baa9502cb71de0cbc4c4deab33c4b981d8f80c955d9e0daf9bb61b05", "b4c7e5e1f9a80936d34bb864575926e746d7d34e7671e0b824b18e7a316167ee", "c987f14b955e357f991c89d2fafa2ac6db876c7f357f06e482365ee91c15a923", "95a1a763a13bff1a36ded210c61fc7ac8cf4448dbbb4935e840bc6bf113fd243",
    "bdf874ac9164a31431cc4daaf5c03db9bc80d91e4f2caa8cece58d415f26b003", "bf5b74a17d8b8e529a64e414d0bd8849a62a8845e751cc3cbaa421c467900e52", "990c3586da11ab33772d9e13446c714c6678004d725e0287daad196da123ab11", "3860ce49f50b12e6dfafa0c0a8ce799c8c40d1e68def09ec1d6263e5e8520877",
    "28d5508edbbe17a3768713a4b75e49d699d830c759cc83d5a895e96e42dd268f", "0b7c14733dba87b1a947e3c00e7e228b630706d46293889e9f539b58933bbdea", "708c3010c18a01b45eb03ea50637b7b33a079f3c730609aba42012cdab7f7911", "17f6dbe43d1a6f061eee270f3e4ec2fbfd7cab5845ffdca3d45c5d3d99da7d74",
    "e9b555a6597c4372e179616c36dfe9cc487a97a79b6ff02aa812a6ad5537ba99", "153503254d00e23353c60af1e1c48aac0238176dff6373047335aad416ae2050", "59eff667148de29d2a6d2442d7761c919b3d1107304aa6540af0552070d83ea5", "e349c36e802cbc0535db5c55a03c10e3d5c561a4b71fcb25030f04fd005d31fb",
    "e2c48996c6285b743d8d62b13b7f58b92ff39e58e7044a8d39a069b43abee259", "2e287181b017eb2b91a8b148bd713bd6e1c52b2f088e38ece1dc9c0f92e9a539", "65a08f195eb51a7436c12a68d6c6eeece26fc832c85181513978fc4da463618b", "da41273703b2ee107c3cf02455cc32c44bc18a7a1bb4f6f3ff6f7d03896f6cea",
    "1a8f5b1bf7496869447baf5f8f34b875300a6fc7deb9f46729c836aab0fc82b3", "241bde634b3b9578f80f084b8f17cb85ee392a79ec928a6a57d1ba9a648a009f", "21bb21c1f35968e9704613a09c535a27b67bb6d8dd3bffe2db0110ce908f2470", "0b31c0db031c50984341c3e251f3ea2d5b8135d181d2b6d26260935d70e3ccf6",
    "a22b540f5cac730591e08c72a205698c9b2d3cf9a04df9941cb485454eac1214", "24d7fe865682d382aa311b3856dc289f91f45eefe0b819d5db86e8ac5e8b547e", "a2bebfb8acf1bca292ac1c84b6a3a32830c84dd545147574f6978c0462c2cf43", "90e8e594f1cf0e3c5828fafddb4b8a36823d1c389c304f9c205fda6a7e88447e"
        ];
    Gi = [
    "0b48be50e49cad13fb3e014f3fa7d68baca7c8a91083dc9c59b379aaab218f15", "df01a5d63b3e3a38382afbd7bc685f343d6192da16ed4b451f15fddab170e22d", "7369c8d5a745423d260623a1f75fae1fb1f81b169d422acd8558e9d5742548bd", "81c07d2bd8771eb4bd84155d38d70531fe662b78f0c44a9aeaea2ed2d6f0ebe1",
    "0896c5c22f0070ebf055dfe8dc1cb20542ef29151aa0771e581e68fe7818ef42", "35c8df1a32aeceedefcbdf6d91d524929b8402a026cb8574e0e3a3342ce211bc", "d967bc14e7abda6c17c2f22a381b84c249757852e99d62c45f160e8915ec21d4", "c8a3831d7c2f24581ec9d15013dfccb5eba69df691a08002b33d4f2fb06ca9f2",
    "9cfbc70db023a48e4535f5838f5ea27f70980d11ecd935b478258e2a4f1006b3", "2da6387292259e69ac0a829ef347699896728c0cc0cadc746dae46fb31864a59", "a5b9a1549c77e4cf8ab8b255a3a0aefaa4cad125d219949c0aeff0c3560ab158", "ed671748a17556419ec942e16b901dbb2fc6df9660324fcbcd6e40f235d75b76",
    "4faff61c1905222baf87d51d45f3558138c87ce54c464cc640b955e7fa3310f8", "3b13dd7b247319e13ce61995bc771ee1ede7363599f08fc5cfda890ea803e0ec", "a70a97707e905629a5e06d186a964f322fffbaa7ed2e781d4d3fede07461f44b", "2d98dbcc0caa2055146e13f50ecf75491dadd36ad2baac56bc08562ec66ce110",
    "b544831dbd34c6c252958151c49a734c6e625e42608c005e797edb6d0a8934b3", "24a0e4d31cba015783501ecdfa7a8ebae3a6bfd32e6d1a3614b11183c80980d4", "546cc3ee5db47bfe9705aa95e2da29f228230353917e5d2b1932fe482fbcfed7", "134d556d0c27f6cc6bf3015c06611625739d889c5789fa75b3c83969cb88b1df",
    "01c0aca470f665eb7182e072bca89bc669ffe5b0296fe21343a8c327c8a84175", "02855a25ccb75b2f8eeac5d1db25044b0aead2cf77021ed94f79f3001e7b8e9d", "b7311db28c45c90d80a1e3d5b27b43f8e380214d6a2c4046c8d40f524d478353", "204d01a17c4fb7b18c2f48270150db67d4b0b9ce8786e03c9550c547fb18029e",
    "f16e5629e9a1c668e1aa79c7887355f5f51b0cbb1f0835e04e7acc53ac55a357", "4197b54c5aaaad47be24dbbc11c1bd3eeb6246542d2f5ae5f4398dd4a7601703", "cbbfd59baddd3a7ce6e375e7d90050e271b13f132df85e1c12be54fe66de81f6", "8a1c8f696f3e773c7eef57ac1389bd0280d558ea7862f01b641ec6da0efefbee",
    "d0509c538a8c3616681d761ae5c6f9d2aaded71890da2496156043082182ec85", "9c3ae48693f91343d0a5f0ecbb7dec9b973bf213678a653b0d9df510652a23c0", "b8065367924a4cfc786036c066caa738349cf1cda70dbfa85cceb4a09f85039b", "6f77274fa6e27935bf89ae373a3b5ada5824bd4b2aec222aebd7fee7a482e9c1",
    "3358eab25f942236f3f4b6ebafe1c3eeeef793836680667c669464c3d4a0847d", "f3024bd5df2aa4aa4d19e551ede93dd075f7953acae53f0f9e8a384e496c5250", "b07e7617e89e28f953d096ec2987ebd8f3e74d933963b82773d37ab1b7a3601d", "c8971334825dd1d67e4c48297292a07a40629675b3e8788efc687385300481ae",
    "697406d24ef88ebf9ca1972c1d528478858ead85782ed410ebbc1f3da48ba807", "836236aac0a8f08a5029115d57e7ef18cb27cce8d2c157a9f4f5615dcc348aea", "c80d0f28df33babe39f6ecbd19a4a6afa853aa4da03b6bd7a806229ded76d2c5", "b9de1176d519a793946792b5417eaf7d2d5126977c5704fc0fcd8e1b2f589b1d",
    "418d19dd28f7e94c51a1782d322e03cba478857424497b4a373fde0fbae4ccd9", "38cbbfa0f4ad2397eed7f76dc3cdb6b06a36660c0775d391ca47213341f659e9", "014f70284efaa5faaba4bb8379ce0204f5aedc28268d82438b5b881fdf2dee4a", "d7d40ed13dad57ca929614a63a00fe3a78f33b30b6fd5f39e4437036dced8d87",
    "af43282f43fa14abaf6c8415fc05ee1ad171d81faa467ddfe5e02eb6895e5688", "dec048f6660e3a2fd8bdec602af59590ec4c6eab834cc0dec8621eb510fba6f7", "adf47693c2fd574d8220a2e70e73ad68e4c332488eb8e731fe600d1e9f6b8f5c", "bf699c18d06bcd73b7cfcef42e68af7ae67fea46e946de6a61faa42c535cfcae",
    "aad5334fc1a9bad4a53e57d11c6accfcefd2e8ab44cb12fb2e664fcbdf5c82b2", "1289626ac2a1402bde7a869eb9ed7807338dd3b2ba8237845db96771cc988008", "1acf053d9bd51c0101941c4c26f66aa5dbad3f5354608577f9e51afe743add50", "f1b5901bea7beb5ae780b6ece977f65b9c628e1dce0ad1e078c746c2f38d0e7f",
    "06b088708ae9ac1117e3a37999c1d75a62e9c9e017018e088aebfb378de29c78", "93acf10942584bf558a2d02d751e34f3f484b001e31924cc21848bf0ddaf1f3d", "8a310049736ff7f049294d8a595f2ca7263a3613840c14b33ef483cdca5bbb8a", "4c7004ccb8f67156267ee35f280db12645de8e552a9312df5769a030a6b46d80",
    "db2e6c06b3c76c1ada42373b29a0591f39856749dfdfb26681166a286fb4f209", "7a3b6f8febdbe4413b67b558689c2e7c1d6d6408f46a6094c74b2281e796e1d9", "00cc835337a31b5350caa9c444c670f78f866e03ef6ec2cbcbc179974145b239", "b90912bbeef8f576961b5efc69641f7a7151708775b67c9e65ed9bb9f5a87bb7",
    "90da203557bed2674055e8a6ab3646c4e1a845ea53d8614ae490065def757615", "a265f2ab98388029aec3afb5cca3a666ab29b6d2c002979c636a3b41b8837a43", "2a81d6db55cf406b1f5842b0a887fe6b2bd88e46298ed3ecc3874c9837734633", "1fde7a2ff7f104265bbd2d0274c033c7583851001dcdb3ded90a9c0977c1f86d",
    "584647557330cee50a53bb15ab2b5a8d8a2b5fb29ffda0e154b26367e5ba1c67", "a879dddb61d40867b6cdf5e38e0fcbdb9a925f622c7de934a308239067da1165", "dc9ba891fd29bb9d9dff2c46c60f95390d3dda52af9ef64ff63d2df72225383b", "92be1ba48b17405678d2243565bb58869bc4b2b879ccc899d2f936c2b8195fd4",
    "7405d86ffb469755b772e4b5fbe7e4a293b5db710008c9006dabd6a9abecdf60", "9a3c789acfe2f233ae1421931ef66334fe743f4877bfcd3a6371fbe378465bd6", "3bf5daee920b1a6413a46c69693f72fc879fffe1a91738084df846be95438928", "93958344a001581ee32c21a728e8050469953bdab783eeaec556a2a5ab1cf3d0",
    "8c2b9233f5f3641bcd76087cf2955b60ae141ed4cade545df60a619a556071d2", "ef3dea09e7bf546050e5df3a8fdf04f66316f6daa4dbb8cbd242d06aaecb1f1d", "bb4dae42c1589c32830277d209be160daf628b5b1992f2b1c5f0eacda1e38e00", "87b7ca8dab93501540485ad18ff869ab4f4b8b016f4543c6a7a936fd351fa5cc",
    "627d24ebbb30d8189c42588645cbf1ff87eec9b7d709c05e649d9b6401a99b3a", "cab8afc1c69b85eaaf3ff36867de1250d98acf2dc6b2e1d71cd32ef0c71402cd", "665f03053d22a9c58de081c4ec3a5eae8a20ebe808561978ae455943c6542d03", "19864cf7754f649ae4646969be65185fb759e698274b456b748b9a51f7fdefd4",
    "cd48609cbe6460a31976529fe4b6fc643745fd2dd3631c8f7576bc8052bd3290", "5fbd42659479bf79de2d3be3cb19e3d4d02883449be1374b6e243aaa87149477", "c25ff682e5c84a0303f11231086e4a578ff52b630600fcbbe71fb719c303b916", "310581b32ef2dc89f4094e0b370b083bd3214a0f3f4504fcb372d3ad4ae206bd",
    "8e34d1e20fce72a8ab40c1ca4e454635eebfe72dea80fd95f9c653e32ede816b", "432ba48e38be49570cf5550b7e8267fc2f1564bc4b64efee9be2b581f90eb96e", "d01d5f34e34262314c87f602c9b1d31cce772c1a023c2c029528cf8d6f9ea1b3", "3b6126c4a8c28772388f382a7a8756e1e2fcca549b00858de2829f87aa20eb08",
    "30a004bd8ae7d5b3e33631aa57cf0718262c0e768062eb36a037f8f0ab7cca79", "29f78f03c91727174e53e6024739be7324fec9b450f4ab82d105bb3acb693327", "558f809689d452e9a46e3de7dafadf87921f17fa24ce874d3ef2a556100a0c88", "4f8440481f974deb9e1786e5fa8e14191b6f797dbc0c8642a1f734bed7cd72b2",
    "15d0b2b5b987d230df63742bbc4b10176a9915cfc7498d48b3fd304757b2a1f5", "9e08978818cf043a6e9cdce9beaf09d61530de061fd7adc9d47d23e75288d092", "91c601bad4a76da8dff262a72346c077ee2515621df907aabcfdbc145904fffd", "9f8b04e24765a0fbb0b434abd3b786d560eceab5f9fce42a85ec05e885e1c66b",
    "afdd0f6eb7de3ab14511da69c7723dec8292bb3ff201ffe60df6e2c5240d1ad7", "cc0c51a3dcb2f6af1f30e3a97af1f32f30da0c7d6ceb897199c9367d4dadd7a8", "43cd2fbda13614692ba492bbb37ceae151d56f81532feb378a186cca0fc8f136", "63ce017e2c7c219976c76b93fec40b5272b25972ba14672e7b720005dffd08f7",
    "82188cc16e371a3b9e985f9f51907c49b017a4a88a14e32b67364ef0de7a12ed", "6588334bdfbfe2e4ead99e7be5be319334e075529a8437c724f61e6cc516d3b2", "aab6b4f935351f01a837b0b3e64eac92eeb8a146af9be97661022cf9c66b983b", "b1557c42d9bed41234e9936b318664d8cb2406e8a4db92678ae12f940f3ca33b",
    "e27b375d296505d37db1f37b457fe4456a92da584a66d0bd4d576e07cd4b1b50", "97f401e188ab16bc92c823ac02f2ae41e22fb5d4ce56257c5527d08892493e33", "e8a1c29a9155831f5c86989681b69d83d738b15b75c69e3862ceddb90b9697f7", "27e0ca28c86738c42f4d2eb84de23a3c5c32c86ddc8ce26f0ba1cad99db42e34",
    "6ac1ae59232143b93924bfd2f159054203b840b8604724f98194e13a7a4207b4", "1b37e0b3fad41c244b19e7c25f22764d888c5c8c61e115576dea399ef2a2732f", "d8c24cc6aa0f725fe4916c4e234e924cb4f7084d2df19c06bdc324866dbd5b4a", "165429619f2e99f030efb223301c47565a48a9a28fc539c182cfc90c4406bafc",
    "a74fe4582285a3791e3cbebf2a1acadbe87da655c9cee94de68fd13461f01f5d", "225e061fcf05171226de40a39bd2b0177ea0deaed23610ade41eee1ea325dfe4", "3cca28000dafcd796cb28c23cfd9bd9e8b6afbb21d3334c396cafd23f67dd8cd", "cd5866f936f12970b3a1fb4bd7386eec4fafff64ff658d14fce92d811f93e9de",
    "6d01241c851cf3efbe72bb177e818f6245fc7e8fb8571f0f480401492f110eed", "e84d5ee2f4252c56236a0f5a8f93ddfcf22240df56e58cf9e5a6647b697ed1f5", "871955a2fbce9e11ca26c13ade04eabb675d69f4ce3e609ce506f37a03978ce5", "2601ba4ae9bb28b05ab7b24e93b9fe6a2159ab589ab5f5e34b9eeac46fd67c97",
    "a59d08d0c9dc897f89459524007b6221700ffa78f6fedfb173c0c3f5e4105b7e", "25fa5fa43d66e66ed80a0d0abfabd94112e15831899249ef96b9df1fa176ad3b", "4423708c3fcd4ed88e92e5cc9b69b7d469af431207e00a0f0f99a0b8ca94bc12", "b67808e3f2c7dcc24ba582cdb8cb33a8f4152347f049cae59945d7027a2c27bd",
    "884abf2e02130bafe933f3c7ffc16d61f68ad06d017bc6b1015a12abf3b14df5", "b7e21f34037462056ce8c398657dc98f20bc62a54f83fd4a6773c65495e81e97", "9a6e0440d17225794e057f76657d5819bf6c9a4287321302e42fb0bb92d40bfd", "c23d5e9604aad674f18cabd4df79f857ca8bf6cde8659bed37c9583a5f1b3d01"
        ];

    //construct a vector commitment of two vectors of scalars
    //res = sum(a[i]*Gi[i] + b[i]*Hi[i])
    this.vector_exponent = function(a, b) {
        var teststart = new Date().getTime();
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        if (a.length > maxN*maxM){throw "Incompatible sizes of a and maxN";}
        var res = I;
        for (var i = 0; i < a.length; i++) {
            res = this.ge_add(this.ge_double_scalarmult_postcomp_vartime_2(a[i], Gi[i], b[i], Hi[i]), res);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //construct a vector commitment of two vectors of scalars
    //res = sum(a[i]*Gi[i] + b[i]*Hi[i])
    this.vector_exponent_raw = function(a, b) {
        var teststart = new Date().getTime();
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        if (a.length > maxN*maxM){throw "Incompatible sizes of a and maxN";}
        var res = I;
        for (var i = 0; i < a.length - 1; i++) {
            res = this.ge_add_raw(this.ge_double_scalarmult_postcomp_vartime_2_raw_output(a[i], Gi[i], b[i], Hi[i]), res);
        }
        res = this.ge_add_raw(this.ge_double_scalarmult_postcomp_vartime_2_raw_output(a[i], Gi[i], b[i], Hi[i]), res);
        res = nacl.ll.pack(res);
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //construct a vector commitment of two vectors of scalars using pippenger
    //res = sum(a[i]*Gi[i] + b[i]*Hi[i])
    this.vector_exponent_pip = function(a, b) {
        var teststart = new Date().getTime();
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        if (a.length > maxN*maxM){throw "Incompatible sizes of a and maxN";}
        var data = [];
        for (var i = 0; i < a.length; i++) {
            data.push({
                scalar: a[i],
                point: Gi[i]
            });
            data.push({
                scalar: b[i],
                point: Hi[i]
            });
        }
        var c = get_pippenger_c(a.length*2);
        var res = pippenger_raw(data, 6);
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //like the above but with supplied points
    //res = sum(a[i]*A[i] + b[i]*B[i])
    this.vector_exponent_custom = function(A, B, a, b) {
        var teststart = new Date().getTime();
        if (A.length !== B.length){throw "Incompatible sizes of A and B";}
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        if (a.length !== A.length){throw "Incompatible sizes of a and A";}
        if (a.length > maxN*maxM){throw "Incompatible sizes of a and maxN";}
        var res = I;
        if (a.length < 32) {
            for (var i = 0; i < a.length; i++) {
                res = this.ge_add(this.ge_double_scalarmult_postcomp_vartime_2(a[i], A[i], b[i], B[i]), res);
            }
        } else {
            var data = [];
            for (var i = 0; i < a.length; i++) {
               data.push({
                    scalar: a[i],
                    point: A[i]
                });
                data.push({
                    scalar: b[i],
                    point: B[i]
                });
            }
            var c = this.get_pippenger_c(a.length*2);
            res = this.pippenger_raw(data, c);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //let's try pippylongstockings
    this.get_pippenger_c = function(N) {
        if (N <= 2) return 5;
        if (N <= 8) return 5;
        if (N <= 16) return 5;
        if (N <= 32) return 6;
        if (N <= 64) return 7;
        if (N <= 128) return 7;
        if (N <= 256) return 8;
    };

    //this is way slower than naive
    this.pippenger = function(data, c) {
        var result = I;
        var buckets = [];
        var groups = Math.floor((253 + c - 1) / c);
        var twoc = d2s(1<<c);
        var sbitv = [];
        for (var i = 0; i < data.length; i++) {
            sbitv[i] = swapEndianC(JSBigInt.parse(swapEndian(data[i].scalar), 16).toString(2));
        }
        for (var k = groups; k-- > 0; ) {
            if (result !== I) {
                result = this.ge_scalarmult(result, twoc);
            }
            for (var i = 0; i < (1<<c); i++) {
                buckets[i] = I;
            }
            for (var i = 0; i < data.length; i++) {
                var bucket = 0;
                for (var j = 0; j < c; j++) {
                    if (sbitv[i][k*c+j] === "1") {
                        bucket |= 1<<j;
                    }
                }
                if (bucket === 0) {
                    continue;
                }
                if (buckets[bucket] !== I) {
                    buckets[bucket] = this.ge_add(buckets[bucket], data[i].point);
                } else {
                    buckets[bucket] = data[i].point;
                }
            }
            var pail = I;
            for (var i = (1<<c)-1; i > 0; i--) {
                if (buckets[i] !== I) {
                    pail = this.ge_add(pail, buckets[i]);
                }
                if (pail !== I) {
                    result = this.ge_add(result, pail);
                }
            }
        }
        return result;
    };

    //lol
    //I'm a genius
    this.pippenger_raw = function(data, c) {
        var result = I;
        var buckets = [];
        var groups = Math.floor((253 + c - 1) / c);
        var twoc = d2s(1<<c);
        var sbitv = [], rawdata = [], ar = [];
        for (var i = 0; i < data.length; i++) {
            sbitv[i] = swapEndianC(JSBigInt.parse(swapEndian(data[i].scalar), 16).toString(2));
            rawdata[i] = nacl.ll.unpack(hextobin(data[i].point));
        }
        for (var k = groups; k-- > 0; ) {
            if (result !== I) {
                result = this.ge_scalarmult_raw(result, twoc);
            }
            for (var i = 0; i < (1<<c); i++) {
                buckets[i] = I;
            }
            for (var i = 0; i < data.length; i++) {
                var bucket = 0;
                for (var j = 0; j < c; j++) {
                    if (sbitv[i][k*c+j] === "1") {
                        bucket |= 1<<j;
                    }
                }
                if (bucket === 0) {
                    continue;
                }
                if (buckets[bucket] !== I) {
                    buckets[bucket] = this.ge_add_raw(buckets[bucket], rawdata[i]);
                } else {
                    //strategy: copy the "raw" rawdata so it doesn't get overwritten later by ge_add_raw via buckets[bucket]
                    //there is probably a better way
                    ar = [];
                    for(var j=0;j<rawdata[i].length;j++) {
                        ar[j] = new Float64Array(rawdata[i][j].length);
                        for(var h=0;h<rawdata[i][j].length;h++){
                            ar[j][h] = rawdata[i][j][h];
                        }
                    }
                    buckets[bucket] = ar;
                }
            }
            var pail = I;
            for (var i = (1<<c)-1; i > 0; i--) {
                if (buckets[i] !== I) {
                    pail = this.ge_add_raw(pail, buckets[i]);
                }
                if (pail !== I) {
                    result = this.ge_add_raw(result, pail);
                }
            }
        }
        return bintohex(nacl.ll.pack(result));
    };

    //create a vector of size n of value x
    //res[i] = x
    function vector_dup(x, n) {
        res = [];
        for (var i = 0; i < n; i++) {
            res[i] = x;
        }
        return res;
    }

    //subtract two vectors of scalars
    //res[i] = a[i] - b[i]
    this.vector_subtract = function(a, b) {
        var teststart = new Date().getTime();
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        var res = [];
        for (var i = 0; i < a.length; i++) {
            res[i] = this.sc_sub(a[i], b[i]);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //add two vectors of scalars
    //res[i] = a[i] + b[i]
    this.vector_add = function(a, b) {
        var teststart = new Date().getTime();
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        var res = [];
        for (var i = 0; i < a.length; i++) {
            res[i] = this.sc_add(a[i], b[i]);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    }

    //fills a vector with powers of x till nth power
    //res[i] = x^i
    this.vector_powers = function(x, n) {
        var teststart = new Date().getTime();
        var res = [];
        if (n === 0){return res;}
        res[0] = I;
        if (n === 1){return res;}
        res[1] = x;
        for (var i = 2; i < n; i++) {
            res[i] = this.sc_mul(res[i-1], x);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //computes the inner product of two vectors of scalars
    //res = sum(a[i]*b[i])
    this.inner_product = function(a, b) {
        var teststart = new Date().getTime();
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        var res = Z;
        for (var i = 0; i < a.length; i++) {
            res = this.sc_muladd(a[i], b[i], res);
        }var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //computes the Hadamard product of two vectors of scalars
    //res[i] = a[i]*b[i]
    this.hadamard = function(a, b) {
        var teststart = new Date().getTime();
        if (a.length !== b.length){throw "Incompatible sizes of a and b";}
        var res = [];
        for (var i = 0; i < a.length; i++) {
            res[i] = this.sc_mul(a[i], b[i]);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //copmutes the "Hadamard product" of two vectors of points
    //res[i] = A[i]+B[i]
    this.hadamard2 = function(A, B) {
        var teststart = new Date().getTime();
        if (A.length !== B.length){throw "Incompatible sizes of A and B";}
        var res = [];
        for (var i = 0; i < A.length; i++) {
            res[i] = this.ge_add(A[i], B[i]);
        }var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //multiply a vector of scalars by a scalar
    //res[i] = a[i]*x
    this.vector_scalar = function(a, x) {
        var teststart = new Date().getTime();
        var res = [];
        for (var i = 0; i < a.length; i++) {
            res[i] = this.sc_mul(a[i], x);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //multiply a vector of points by a scalar
    //res[i] = x*A[i]
    this.vector_scalar2 = function(A, x) {
        var teststart = new Date().getTime();
        var res = [];
        for (var i = 0; i < A.length; i++) {
            res[i] = this.ge_scalarmult(A[i], x);
        }
        var testfinish = new Date().getTime() - teststart;
        return res;
    };

    //slice a vector based on start and stop indices
    //res[0] = a[start], res[end] = a[stop-1]
    function slice(a, start, stop) {
        if (start >= a.length){throw "Invalid start index";}
        if (stop > a.length){throw "Invalid stop index";}
        if (start >= stop){throw "Invalid start/stop indices";}
        var res = [];
        for (var i = start; i < stop; i++) {
            res[i-start] = a[i];
        }
        return res;
    }
    //end Bulletproof functions

    this.bulletproof_PROVE = function(svs, gamma) {
        var bpteststart = new Date().getTime();

        if (svs.length !== gamma.length) {
            throw "Incompatible sizes of sv and gamma";
        }
        //this.init_exponents(); //cache them instead


        var sv = [];
        //convert amounts to scalars
        for (var i = 0; i < svs.length; i++) {
            sv[i] = d2s(svs[i]);
        }

        var logN = 6;
        var N = 64;
        var M, logM;
        for (logM = 0; (M = 1<<logM) <= maxM && M < sv.length; logM++) {
            if (M > maxM) {
                throw "sv/gamma are too large";
            }
        }
        var logMN = logM + logN;
        var MN = M * N;
        var V = [], aL = [], aR = [];

        for (var i = 0; i < sv.length; i++) {
            V[i] = commit(sv[i], gamma[i]); //sv[i]*H + gamma[i]*G
            V[i] = this.ge_scalarmult(V[i], INV_EIGHT);
        }

        var svb; //to hold bit value for amount - I hope this works
        for (var j = 0; j < M; j++) {
            svb = d2b(svs[j]);
            for (var i = N; i > 0; ) {
                i--;
                if (j >= sv.length) {
                    aL[j*N+i] = Z;
                } else if (svb[i] === "1") {
                    aL[j*N+i] = I;
                } else {
                    aL[j*N+i] = Z;
                }
                aR[j*N+i] = this.sc_sub(aL[j*N+i], I);
            }
        }

        var hash_cache = array_hash_to_scalar(V);

        // PAPER LINES 38-39
        var alpha = this.random_scalar();
        var ve = this.vector_exponent_pip(aL, aR);
        var A = this.ge_add(ve, this.ge_scalarmult_base(alpha));
        A = this.ge_scalarmult(A, INV_EIGHT);


        // PAPER LINES 40-42
        var sL = [], sR = [];
        for (var i = 0; i < MN; i++) {
            sL[i] = this.random_scalar();
            sR[i] = this.random_scalar();
        }
        var rho = this.random_scalar();
        ve = this.vector_exponent_pip(sL, sR);
        var S = this.ge_add(ve, this.ge_scalarmult_base(rho));
        S = this.ge_scalarmult(S, INV_EIGHT);

        // PAPER LINES 43-45
        var y = this.hash_to_scalar(hash_cache + A + S);
        var z = this.hash_to_scalar(y);
        hash_cache = z;

        // Polynomial construction by coefficients
        var zMN = vector_dup(z, MN);
        var l0 = this.vector_subtract(aL, zMN);
        var l1 = sL;

        // This computes the ugly sum/concatenation from PAPER LINE 65
        var zero_twos = [];
        var twoN = vector_powers(TWO, maxN);
        var zpow = this.vector_powers(z, M+2);
        for (var i = 0; i < MN; i++) {
            zero_twos[i] = Z;
            for (var j = 1; j <= M; j++) {
                if (i >= (j-1)*N && i < j*N) {
                    if (j+1 >= zpow.length){throw "invalid zpow index";}
                    if (i-(j-1)*N >= twoN.length){throw "invalid twoN index";}
                    zero_twos[i] = this.sc_muladd(zpow[j+1], twoN[i-(j-1)*N], zero_twos[i]);
                }
            }
        }

        var r0 = this.vector_add(aR, zMN);
        var yMN = this.vector_powers(y, MN);
        r0 = this.hadamard(r0, yMN);
        r0 = this.vector_add(r0, zero_twos);
        var r1 = this.hadamard(yMN, sR);

        // Polynomial construction before PAPER LINE 46
        var t1_1 = this.inner_product(l0, r1);
        var t1_2 = this.inner_product(l1, r0);
        var t1 = this.sc_add(t1_1, t1_2);
        var t2 = this.inner_product(l1, r1);

        // PAPER LINES 47-48
        var tau1 = this.random_scalar(), tau2 = this.random_scalar();
        var T1 = this.ge_scalarmult(commit(t1, tau1), INV_EIGHT);
        var T2 = this.ge_scalarmult(commit(t2, tau2), INV_EIGHT);

        // PAPER LINES 49-51
        var x = this.hash_to_scalar(hash_cache + z + T1 + T2);
        hash_cache = x;


        // PAPER LINES 52-53
        var taux = this.sc_mul(tau1, x);
        var xsq = this.sc_mul(x, x);
        taux = this.sc_muladd(tau2, xsq, taux);
        for (var j = 1; j <= sv.length; j++) {
            if (j+1 >= zpow.length){throw "invalid zpow index";}
            taux = this.sc_muladd(zpow[j+1], gamma[j-1], taux);
        }
        var mu = this.sc_muladd(x, rho, alpha);

        // PAPER LINES 54-57
        //var l = l0;
        var l = this.vector_add(l0, vector_scalar(l1, x));
        //var r = r0;
        var r = this.vector_add(r0, vector_scalar(r1, x));

        var t = this.inner_product(l, r);

        /*//debug
        var t0 = this.inner_product(l0, r0);
        var test_t = this.sc_muladd(t1, x, t0);
        test_t = this.sc_muladd(t2, xsq, test_t);
        console.log("debug: " + (test_t == t));
        //end debug*/

        // PAPER LINES 32-33
        var x_ip = this.hash_to_scalar(hash_cache + x + taux + mu + t);
        hash_cache = x_ip;

        // These are used in the inner product rounds
        var nprime = MN;
        var Gprime = [],
        Hprime = [],
        aprime = [],
        bprime = [];
        var yinv = this.invert(y);
        var yinvpow = I;
        for (var i = 0; i < MN; i++) {
            Gprime[i] = Gi[i];
            Hprime[i] = this.ge_scalarmult(Hi[i], yinvpow);
            yinvpow = this.sc_mul(yinvpow, yinv);
            aprime[i] = l[i];
            bprime[i] = r[i];
        }
        var L = [], R = [];
        var round = 0;
        var w = []; // this is the challenge x in the inner product protocol
        // PAPER LINE 13
        var tmp;
        while (nprime > 1) {
            // PAPER LINE 15
            nprime /= 2;

           // console.log("round: " + round + " nprime: " + nprime);
            // PAPER LINES 16-17
            var cL = this.inner_product(slice(aprime, 0, nprime), slice(bprime, nprime, bprime.length));
            var cR = this.inner_product(slice(aprime, nprime, aprime.length), slice(bprime, 0, nprime));

            // PAPER LINES 18-19
            L[round] = this.vector_exponent_custom(slice(Gprime, nprime, Gprime.length), slice(Hprime, 0, nprime), slice(aprime, 0, nprime), slice(bprime, nprime, bprime.length));
            tmp = this.sc_mul(cL, x_ip);
            L[round] = this.ge_add(L[round], this.ge_scalarmult(H, tmp));
            L[round] = this.ge_scalarmult(L[round], INV_EIGHT);
            R[round] = this.vector_exponent_custom(slice(Gprime, 0, nprime), slice(Hprime, nprime, Hprime.length), slice(aprime, nprime, aprime.length), slice(bprime, 0, nprime));
            tmp = this.sc_mul(cR, x_ip);
            R[round] = this.ge_add(R[round], this.ge_scalarmult(H, tmp));
            R[round] = this.ge_scalarmult(R[round], INV_EIGHT);

            // PAPER LINES 21-22
            w[round] = this.hash_to_scalar(hash_cache + L[round] + R[round]);
            hash_cache = w[round];

            // PAPER LINES 24-25
            var winv = this.invert(w[round]);
            Gprime = this.hadamard2(vector_scalar2(slice(Gprime, 0, nprime), winv), this.vector_scalar2(slice(Gprime, nprime, Gprime.length), w[round]));
            Hprime = this.hadamard2(vector_scalar2(slice(Hprime, 0, nprime), w[round]), this.vector_scalar2(slice(Hprime, nprime, Hprime.length), winv));

            // PAPER LINES 28-29
            aprime = this.vector_add(this.vector_scalar(slice(aprime, 0, nprime), w[round]), this.vector_scalar(slice(aprime, nprime, aprime.length), winv));
            bprime = this.vector_add(this.vector_scalar(slice(bprime, 0, nprime), winv), this.vector_scalar(slice(bprime, nprime, bprime.length), w[round]));

            round++;
        }

        // PAPER LINE 58 (with inclusions from PAPER LINE 8 and PAPER LINE 20)
        var bp = {
            V: V,
            A: A,
            S: S,
            T1: T1,
            T2: T2,
            taux: taux,
            mu: mu,
            L: L,
            R: R,
            a: aprime[0],
            b: bprime[0],
            t: t
        };
        var bptestfinish = new Date().getTime() - bpteststart;

        return bp;
    };

    // reargances array to specific indices.
    this.rearrange = function(arr, ind) {
        var new_arr = [];

        for (j = 0; j < ind.length; j++) {
            new_arr.push(arr[ind[j]]);
        }

        return new_arr;
    };

    this.construct_tx = function(keys, sources, dsts, fee_amount, payment_id, pid_encrypt, realDestViewKey, unlock_time, rct) {
        //we move payment ID stuff here, because we need txkey to encrypt
        var txkey = this.random_keypair();
        console.log(txkey);
        var extra = '';
        if (payment_id) {
            if (pid_encrypt && payment_id.length !== INTEGRATED_ID_SIZE * 2) {
                throw "payment ID must be " + INTEGRATED_ID_SIZE + " bytes to be encrypted!";
            }
            console.log("Adding payment id: " + payment_id);
            if (pid_encrypt) { //get the derivation from our passed viewkey, then hash that + tail to get encryption key
                var pid_key = this.cn_fast_hash(this.generate_key_derivation(realDestViewKey, txkey.sec) + ENCRYPTED_PAYMENT_ID_TAIL.toString(16)).slice(0, INTEGRATED_ID_SIZE * 2);
                console.log("Txkeys:", txkey, "Payment ID key:", pid_key);
                payment_id = this.hex_xor(payment_id, pid_key);
            }
            var nonce = this.get_payment_id_nonce(payment_id, pid_encrypt);
            console.log("Extra nonce: " + nonce);
            extra = this.add_nonce_to_extra(extra, nonce);
        }

        // for sending to a subaddress, need to generate new tx public key

        //var sub_addr_decoded = this.decode_address(dsts[0].address); // for example dest[0] is subaddress
        //txkey.pub = ge_scalarmult(sub_addr_decoded.spend, txkey.sec);

        var tx = {
            unlock_time: unlock_time,
            version: rct ? CURRENT_TX_VERSION : OLD_TX_VERSION,
            extra: extra,
            prvkey: '',
            vin: [],
            vout: []
        };
        if (rct) {
            tx.rct_signatures = {};
        } else {
            tx.signatures = [];
        }

        //tx.extra = this.add_pub_key_to_extra(tx.extra, txkey.pub);
        tx.prvkey = txkey.sec;

        var in_contexts  = [];

        var is_rct_coinbases = []; // monkey patching to solve problem of
                                   // not being able to spend coinbase ringct txs.

        var inputs_money = JSBigInt.ZERO;
        var i, j;

        console.log('Sources: ');

        for (i = 0; i < sources.length; i++)
        {
            console.log(i + ': ' + this.formatMoneyFull(sources[i].amount));
            if (sources[i].real_out >= sources[i].outputs.length) {
                throw "real index >= outputs.length";
            }
            inputs_money = inputs_money.add(sources[i].amount);

            // sets res.mask among other things. mask is identity for non-rct transactions
            // and for coinbase ringct (type = 0) txs.
            var res = this.generate_key_image_helper_rct(keys, sources[i].real_out_tx_key, sources[i].real_out_in_tx, sources[i].mask); //mask will be undefined for non-rct

            in_contexts.push(res.in_ephemeral);

            // now we mark if this is ringct coinbase txs. such transactions
            // will have identity mask. Non-ringct txs will have  sources[i].mask set to null.
            // this only works if beckend will produce masks in get_unspent_outs for
            // coinbaser ringct txs.
            is_rct_coinbases.push((sources[i].mask ? sources[i].mask === I : 0));


            if (res.in_ephemeral.pub !== sources[i].outputs[sources[i].real_out].key) {
                throw "in_ephemeral.pub != source.real_out.key";
            }
            var input_to_key = {};
            input_to_key.type = "input_to_key";
            input_to_key.amount = sources[i].amount;
            input_to_key.k_image = res.image;
            input_to_key.key_offsets = [];
            for (j = 0; j < sources[i].outputs.length; ++j) {
                input_to_key.key_offsets.push(sources[i].outputs[j].index);
            }
            input_to_key.key_offsets = this.abs_to_rel_offsets(input_to_key.key_offsets);
            tx.vin.push(input_to_key);
        }


        // new to sort key_imags and associated variables.

        var ins_order = [];

        for (var i = 0; i < tx.vin.length; i++){
            ins_order.push(i);
        }

        // determine indexes which we should sort.
        ins_order.sort(function(i0, i1) {
            if (tx.vin[i0].k_image < tx.vin[i1].k_image) {
                return 1;
            }

            if (tx.vin[i0].k_image > tx.vin[i1].k_image) {
                return -1;
            }

            return 0;
        });

        // sort key images along with rources and contexts.
        tx.vin = rearrange(tx.vin , ins_order);
        sources = rearrange(sources, ins_order);
        in_contexts = rearrange(in_contexts, ins_order);


        var outputs_money = JSBigInt.ZERO;
        var out_index = 0;
        var amountKeys = []; //rct only

        for (i = 0; i < dsts.length; ++i) {

            if (new JSBigInt(dsts[i].amount).compare(0) < 0) {
                throw "dst.amount < 0"; //amount can be zero if no change
            }

            dsts[i].keys = this.decode_address(dsts[i].address);

            if (this.is_subaddress(dsts[i].address)) {
               txkey.pub = ge_scalarmult(dsts[i].keys.spend, txkey.sec);
            }

            var out_derivation;

            // if destination public view and spend keys matches our own public keys
            // we send change to ourself
            if (dsts[i].keys.view === keys.view.pub && dsts[i].keys.spend === keys.spend.pub)             {
                out_derivation = this.generate_key_derivation(txkey.pub, keys.view.sec);
            }
            else {
                out_derivation = this.generate_key_derivation(dsts[i].keys.view, txkey.sec);
            }

            if (rct) {
                amountKeys.push(this.derivation_to_scalar(out_derivation, out_index));
            }

            var out_ephemeral_pub = this.derive_public_key(
                out_derivation, out_index, dsts[i].keys.spend);

            var out = {
                amount: dsts[i].amount.toString()
            };

            // txout_to_key
            out.target = {
                type: "txout_to_key",
                key: out_ephemeral_pub
            };

            tx.vout.push(out);

            ++out_index;

            outputs_money = outputs_money.add(dsts[i].amount);
        }

        tx.extra = this.add_pub_key_to_extra(tx.extra, txkey.pub);

        if (outputs_money.add(fee_amount).compare(inputs_money) > 0) {
            throw "outputs money (" + this.formatMoneyFull(outputs_money) + ") + fee (" + this.formatMoneyFull(fee_amount) + ") > inputs money (" + this.formatMoneyFull(inputs_money) + ")";
        }


        if (!rct) {
            for (i = 0; i < sources.length; ++i) {
                var src_keys = [];
                for (j = 0; j < sources[i].outputs.length; ++j) {
                    src_keys.push(sources[i].outputs[j].key);
                }
                var sigs = this.generate_ring_signature(this.get_tx_prefix_hash(tx), tx.vin[i].k_image, src_keys,
                    in_contexts[i].sec, sources[i].real_out);
                tx.signatures.push(sigs);
            }
        } else { //rct
            var txnFee = fee_amount;
            var keyimages = [];
            var inSk = [];
            var inAmounts = [];
            var mixRing = [];
            var indices = [];
            for (i = 0; i < tx.vin.length; i++) {
                keyimages.push(tx.vin[i].k_image);
                inSk.push({
                    x: in_contexts[i].sec,
                    a: in_contexts[i].mask
                });
                inAmounts.push(tx.vin[i].amount);

                //if (in_contexts[i].mask !== I) {//if input is rct (has a valid mask), 0 out amount
                    //tx.vin[i].amount = "0";
                //}

                if (in_contexts[i].mask !== I || is_rct_coinbases[i] === true)
                {
                    // if input is rct (has a valid mask), 0 out amount
                    // coinbase ringct txs also have mask === I, so their amount
                    // must be set to zero when spending them.
                    tx.vin[i].amount = "0";
                }

                mixRing[i] = [];
                for (j = 0; j < sources[i].outputs.length; j++) {
                    mixRing[i].push({
                        dest: sources[i].outputs[j].key,
                        mask: sources[i].outputs[j].commit
                    });
                }
                indices.push(sources[i].real_out);
            }
            var outAmounts = [];
            for (i = 0; i < tx.vout.length; i++) {
                outAmounts.push(tx.vout[i].amount);
                tx.vout[i].amount = "0"; //zero out all rct outputs
            }
            var tx_prefix_hash = this.get_tx_prefix_hash(tx);
            tx.rct_signatures = genRct(tx_prefix_hash, inSk, keyimages, /*destinations, */inAmounts, outAmounts, mixRing, amountKeys, indices, txnFee);

        }
        console.log(tx);
        return tx;
    };
    this.create_transaction = function(pub_keys, sec_keys, dsts, outputs, mix_outs, fake_outputs_count, fee_amount, payment_id, pid_encrypt, realDestViewKey, unlock_time, rct) {
        unlock_time = unlock_time || 0;
        mix_outs = mix_outs || [];
        var i, j;
        if (dsts.length === 0) {
            throw 'Destinations empty';
        }
        if (mix_outs.length !== outputs.length && fake_outputs_count !== 0) {
            throw 'Wrong number of mix outs provided (' + outputs.length + ' outputs, ' + mix_outs.length + ' mix outs)';
        }
        for (i = 0; i < mix_outs.length; i++) {
            if ((mix_outs[i].outputs || []).length < fake_outputs_count) {
                throw 'Not enough outputs to mix with';
            }
        }
        var keys = {
            view: {
                pub: pub_keys.view,
                sec: sec_keys.view
            },
            spend: {
                pub: pub_keys.spend,
                sec: sec_keys.spend
            }
        };
        if (!this.valid_keys(keys.view.pub, keys.view.sec, keys.spend.pub, keys.spend.sec)) {
            throw "Invalid secret keys!";
        }
        var needed_money = JSBigInt.ZERO;
        for (i = 0; i < dsts.length; ++i) {
            needed_money = needed_money.add(dsts[i].amount);
            if (needed_money.compare(UINT64_MAX) !== -1) {
                throw "Output overflow!";
            }
        }
        var found_money = JSBigInt.ZERO;
        var sources = [];
        console.log('Selected transfers: ', outputs);
        for (i = 0; i < outputs.length; ++i) {
            found_money = found_money.add(outputs[i].amount);
            if (found_money.compare(UINT64_MAX) !== -1) {
                throw "Input overflow!";
            }
            var src = {
                outputs: []
            };
            src.amount = new JSBigInt(outputs[i].amount).toString();
            if (mix_outs.length !== 0) {
                // Sort fake outputs by global index
                mix_outs[i].outputs.sort(function(a, b) {
                    return new JSBigInt(a.global_index).compare(b.global_index);
                });
                j = 0;
                while ((src.outputs.length < fake_outputs_count) && (j < mix_outs[i].outputs.length)) {
                    var out = mix_outs[i].outputs[j];
                    if (out.global_index === outputs[i].global_index) {
                        console.log('got mixin the same as output, skipping');
                        j++;
                        continue;
                    }
                    var oe = {};
                    oe.index = out.global_index.toString();
                    oe.key = out.public_key;
                    if (rct){
                        if (out.rct){
                            oe.commit = out.rct.slice(0,64); //add commitment from rct mix outs
                        } else {
                            if (outputs[i].rct) {throw "mix rct outs missing commit";}
                            oe.commit = zeroCommit(d2s(src.amount)); //create identity-masked commitment for non-rct mix input
                        }
                    }
                    src.outputs.push(oe);
                    j++;
                }
            }
            var real_oe = {};
            real_oe.index = new JSBigInt(outputs[i].global_index || 0).toString();
            real_oe.key = outputs[i].public_key;
            if (rct){
                if (outputs[i].rct) {
                    real_oe.commit = outputs[i].rct.slice(0,64); //add commitment for real input
                } else {
                    real_oe.commit = zeroCommit(d2s(src.amount)); //create identity-masked commitment for non-rct input
                }
            }
            var real_index = src.outputs.length;
            for (j = 0; j < src.outputs.length; j++) {
                if (new JSBigInt(real_oe.index).compare(src.outputs[j].index) < 0) {
                    real_index = j;
                    break;
                }
            }
            // Add real_oe to outputs
            src.outputs.splice(real_index, 0, real_oe);
            src.real_out_tx_key = outputs[i].tx_pub_key;
            // Real output entry index
            src.real_out = real_index;
            src.real_out_in_tx = outputs[i].index;
            if (rct){
                if (outputs[i].rct) {
                    src.mask = outputs[i].rct.slice(64,128); //encrypted or idenity mask for coinbase txs.
                } else {
                    src.mask = null; //will be set by generate_key_image_helper_rct
                }
            }
            sources.push(src);
        }
        console.log('sources: ', sources);
        var change = {
            amount: JSBigInt.ZERO
        };
        var cmp = needed_money.compare(found_money);
        if (cmp < 0) {
            change.amount = found_money.subtract(needed_money);
            if (change.amount.compare(fee_amount) !== 0) {
                throw "early fee calculation != later";
            }
        } else if (cmp > 0) {
            throw "Need more money than found! (have: " + cnUtil.formatMoney(found_money) + " need: " + cnUtil.formatMoney(needed_money) + ")";
        }
        return this.construct_tx(keys, sources, dsts, fee_amount, payment_id, pid_encrypt, realDestViewKey, unlock_time, rct);
    };

    this.estimateRctSize = function(inputs, mixin, outputs) {
        var size = 0;
        //size += outputs * 6306; //borromean range proofs + commitment(32) + ecdh_info(64) + amount(1) + pubkey(32) + type(1)
        size += outputs * (32 + 1 + 1 + 64 + 32) + 740 //bulletproofs, yes this function is currently brittle
        size += ((mixin + 1) * 4 + 32 + 8) * inputs; //key offsets + key image + amount
        size += 64 * (mixin + 1) * inputs + 64 * inputs; //signature + pseudoOuts/cc
        size += 74; //extra + whatever, assume long payment ID
        return size;
    };

    this.estimateRctSizeNew = function(inputs, mixin, outputs, extra_size, bulletproof)
    {
      var size = 0;
      size += 1 + 6;
      size += inputs * (1+6+(mixin+1)*2+32);
      size += outputs * (6+32);
      size += extra_size;
      size += 1;

      if (bulletproof)
      {
        var log_padded_outputs = 0;
        while ((1<<log_padded_outputs) < outputs)
          ++log_padded_outputs;
        size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;
      }
      else
        size += (2*64*32+32+64*32) * outputs;


      size += inputs * (64 * (mixin+1) + 32);

      size += 32 * inputs;

      size += 2 * 32 * outputs;
      size += 32 * outputs;
      size += 4;

      return size;
    };

    this.estimate_tx_size = function(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof)
    {
      if (use_rct)
        return estimateRctSizeNew(n_inputs, mixin, n_outputs, extra_size, bulletproof);
      else
        return n_inputs * (mixin+1) * 80 + extra_size;
    };

    this.estimate_tx_weight = function(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof)
    {
      var size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof);
      if (use_rct && bulletproof && n_outputs > 2)
      {
        var bp_base = 368;
        var log_padded_outputs = 2;
        while ((1<<log_padded_outputs) < n_outputs)
          ++log_padded_outputs;
        var nlr = 2 * (6 + log_padded_outputs);
        var bp_size = 32 * (9 + nlr);
        var bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
        size += bp_clawback;
      }
      return size;
    };

    this.calculate_fee = function(fee_per_kb, bytes, fee_multiplier)
    {
      var kB = (bytes + 1023) / 1024;
      return kB * fee_per_kb * fee_multiplier;
    };

    this.calculate_fee_from_weight = function(base_fee, weight, fee_multiplier, fee_quantization_mask)
    {
      var fee = weight * base_fee * fee_multiplier;
      fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
      return fee;
    };

    this.estimate_fee = function(use_per_byte_fee, use_rct, n_inputs, mixin,  n_outputs, extra_size, bulletproof, base_fee, fee_multiplier, fee_quantization_mask)
    {
      if (use_per_byte_fee)
      {
        var estimated_tx_weight = estimate_tx_weight(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof);
        return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
      }
      else
      {
        var estimated_tx_size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof);
        return calculate_fee(base_fee, estimated_tx_size, fee_multiplier);
      }
    };

    function trimRight(str, char) {
        while (str[str.length - 1] == char) str = str.slice(0, -1);
        return str;
    }

    function padLeft(str, len, char) {
        while (str.length < len) {
            str = char + str;
        }
        return str;
    }

    this.printDsts = function(dsts) {
        for (var i = 0; i < dsts.length; i++) {
            console.log(dsts[i].address + ': ' + this.formatMoneyFull(dsts[i].amount));
        }
    };

    this.formatMoneyFull = function(units) {
        units = units.toString();
        var symbol = units[0] === '-' ? '-' : '';
        if (symbol === '-') {
            units = units.slice(1);
        }
        var decimal;
        if (units.length >= config.coinUnitPlaces) {
            decimal = units.substr(units.length - config.coinUnitPlaces, config.coinUnitPlaces);
        } else {
            decimal = padLeft(units, config.coinUnitPlaces, '0');
        }
        return symbol + (units.substr(0, units.length - config.coinUnitPlaces) || '0') + '.' + decimal;
    };

    this.formatMoneyFullSymbol = function(units) {
        return this.formatMoneyFull(units) + ' ' + config.coinSymbol;
    };

    this.formatMoney = function(units) {
        var f = trimRight(this.formatMoneyFull(units), '0');
        if (f[f.length - 1] === '.') {
            return f.slice(0, f.length - 1);
        }
        return f;
    };

    this.formatMoneySymbol = function(units) {
        return this.formatMoney(units) + ' ' + config.coinSymbol;
    };

    this.parseMoney = function(str) {
        if (!str) return JSBigInt.ZERO;
        var negative = str[0] === '-';
        if (negative) {
            str = str.slice(1);
        }
        var decimalIndex = str.indexOf('.');
        if (decimalIndex == -1) {
            if (negative) {
                return JSBigInt.multiply(str, config.coinUnits).negate();
            }
            return JSBigInt.multiply(str, config.coinUnits);
        }
        if (decimalIndex + config.coinUnitPlaces + 1 < str.length) {
            str = str.substr(0, decimalIndex + config.coinUnitPlaces + 1);
        }
        if (negative) {
            return new JSBigInt(str.substr(0, decimalIndex)).exp10(config.coinUnitPlaces)
                .add(new JSBigInt(str.substr(decimalIndex + 1)).exp10(decimalIndex + config.coinUnitPlaces - str.length + 1)).negate;
        }
        return new JSBigInt(str.substr(0, decimalIndex)).exp10(config.coinUnitPlaces)
            .add(new JSBigInt(str.substr(decimalIndex + 1)).exp10(decimalIndex + config.coinUnitPlaces - str.length + 1));
    };

    this.decompose_amount_into_digits = function(amount) {
        /*if (dust_threshold === undefined) {
         dust_threshold = config.dustThreshold;
         }*/
        amount = amount.toString();
        var ret = [];
        while (amount.length > 0) {
            //split all the way down since v2 fork
            /*var remaining = new JSBigInt(amount);
             if (remaining.compare(config.dustThreshold) <= 0) {
             if (remaining.compare(0) > 0) {
             ret.push(remaining);
             }
             break;
             }*/
            //check so we don't create 0s
            if (amount[0] !== "0"){
                var digit = amount[0];
                while (digit.length < amount.length) {
                    digit += "0";
                }
                ret.push(new JSBigInt(digit));
            }
            amount = amount.slice(1);
        }
        return ret;
    };

    this.decompose_tx_destinations = function(dsts, rct) {
        var out = [];
        if (rct) {
            for (var i = 0; i < dsts.length; i++) {
                out.push({
                    address: dsts[i].address,
                    amount: dsts[i].amount
                });
            }
        } else {
            for (var i = 0; i < dsts.length; i++) {
                var digits = this.decompose_amount_into_digits(dsts[i].amount);
                for (var j = 0; j < digits.length; j++) {
                    if (digits[j].compare(0) > 0) {
                        out.push({
                            address: dsts[i].address,
                            amount: digits[j]
                        });
                    }
                }
            }
        }
        return out.sort(function(a,b){
            return a["amount"] - b["amount"];
        });
    };

    this.is_tx_unlocked = function(unlock_time, blockchain_height) {
        if (!config.maxBlockNumber) {
            throw "Max block number is not set in config!";
        }
        if (unlock_time < config.maxBlockNumber) {
            // unlock time is block height
            return blockchain_height >= unlock_time;
        } else {
            // unlock time is timestamp
            var current_time = Math.round(new Date().getTime() / 1000);
            return current_time >= unlock_time;
        }
    };

    this.tx_locked_reason = function(unlock_time, blockchain_height) {
        if (unlock_time < config.maxBlockNumber) {
            // unlock time is block height
            var numBlocks = unlock_time - blockchain_height;
            if (numBlocks <= 0) {
                return "Transaction is unlocked";
            }
            var unlock_prediction = moment().add(numBlocks * config.avgBlockTime, 'seconds');
            //return "Will be unlocked in " + numBlocks + " blocks, ~" + unlock_prediction.fromNow(true) + ", " + unlock_prediction.calendar() + "";
            return "Will be unlocked in " + numBlocks + " blocks, ~" + unlock_prediction.fromNow(true);
        } else {
            // unlock time is timestamp
            var current_time = Math.round(new Date().getTime() / 1000);
            var time_difference = unlock_time - current_time;
            if(time_difference <= 0) {
                return "Transaction is unlocked";
            }
            var unlock_moment = moment(unlock_time * 1000);
            //return "Will be unlocked " + unlock_moment.fromNow() + ", " + unlock_moment.calendar();
            return "Will be unlocked " + unlock_moment.fromNow();
        }
    };


    //decode amount and mask and check against commitment
    // from https://xmr.llcoins.net/js/site.js
    // from https://xmr.llcoins.net/js/site.js
    this.decodeRct = function(rv, i, der){
        var key = derivation_to_scalar(der, i);
        var ecdh = decode_rct_ecdh(rv.ecdhInfo[i], key);
        //console.log(ecdh);
        var Ctmp = commit(ecdh.amount, ecdh.mask);
        //console.log(Ctmp);
        if (Ctmp !== rv.outPk[i]){
            throw "mismatched commitments!";
        }
        ecdh.amount = s2d(ecdh.amount);
        return ecdh;
    };

    function assert(stmt, val) {
        if (!stmt) {
            throw "assert failed" + (val !== undefined ? ': ' + val : '');
        }
    }

    return this;
})(config);
