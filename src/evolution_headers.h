//
// Created by mwo on 5/11/15.
//

#ifndef XMREG01_EVOLUTION_HEADERS_H_H
#define XMREG01_EVOLUTION_HEADERS_H_H

#define DB_LMDB 3
#define BLOCKCHAIN_DB DB_LMDB


#define UNSIGNED_TX_PREFIX "Evolution unsigned tx set\003"
#define SIGNED_TX_PREFIX "Evolution signed tx set\003"
#define KEY_IMAGE_EXPORT_FILE_MAGIC "Evolution key image export\002"
#define OUTPUT_EXPORT_FILE_MAGIC "Evolution output export\003"

#define FEE_ESTIMATE_GRACE_BLOCKS 10 // estimate fee valid for that many blocks

#include "version.h"

#include "net/http_client.h"
#include "storages/http_abstract_invoke.h"

#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/blockchain.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "device/device_default.hpp"

#include "wallet/wallet2.h"

#include "serialization/binary_utils.h"

#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"

#include "easylogging++.h"

#include "common/base58.h"

#include "string_coding.h"


#endif //XMREG01_EVOLUTION_HEADERS_H_H
