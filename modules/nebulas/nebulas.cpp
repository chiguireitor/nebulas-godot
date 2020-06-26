
#include "nebulas.h"

#include "core/crypto/crypto_core.h"
#include "core/bind/core_bind.h"

#include "keccak-tiny/keccak-tiny.h"
#include "libbtc/ripemd160.h"
#include "libbtc/base58.h"

/*#include <btc/utils.h>
#include <btc/bip32.h>
#include <btc/base58.h>
#include <btc/sha2.h>
#include <btc/hash.h>
#include <btc/ripemd160.h>
#include <btc/script.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>


#define DUST_LIMIT 560
#define MIN_RELAY_FEE 251

const btc_chainparams dash_chainparams_main = {
    "dash",
    0x4C,
    0x10,
    "ds",
    0xCC,
    0x0488ADE4,
    0x0488B21E,
    {0xbf, 0x0c, 0x6b, 0xbd},
    {0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00},
    9999,
    {{"dnsseed.dash.org"}, 0},
};

const btc_chainparams mona_chainparams_main = {
    "mona",
    0x32,
    0x05,
    "mn",
    0xB0,
    0x0488ADE4,
    0x0488B21E,
    {0xfb, 0xc0, 0xb6, 0xdb},
    {0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00},
    9401,
    {{"dnsseed.monacoin.org"}, 0},
};

// from https://github.com/manicmaniac/arc4/blob/master/arc4.c
typedef struct arc4_state {
    unsigned char x;
    unsigned char y;
    unsigned char s[256];
} arc4_state;

static void arc4_init(arc4_state *state, const unsigned char *key, size_t keylen) {
    int i;
    unsigned char j, k;

    for (i = 0; i < 256; i++) {
        state->s[i] = (unsigned char)i;
    }
    state->x = 0;
    state->y = 0;
    j = 0;
    for (i = 0; i < 256; i++) {
        j += state->s[i] + key[i % keylen];
        k = state->s[i];
        state->s[i] = state->s[j];
        state->s[j] = k;
    }
}

static void arc4_crypt(arc4_state *state, unsigned char *buf, size_t buflen) {
    unsigned char x;
    unsigned char y;
    unsigned char *s;
    size_t i;
    unsigned char sx;
    unsigned char sy;

    x = state->x;
    y = state->y;
    s = state->s;
    for (i = 0; i < buflen; i++) {
        x++;
        y += s[x];
        sx = s[x];
        sy = s[y];
        s[x] = sy;
        s[y] = sx;
        buf[i] ^= s[(sx + sy) & 0xFF];
    }
    state->x = x;
    state->y = y;
}

static uint8_t buffer_whex_to_uint8[TO_UINT8_HEX_BUF_LEN];

uint8_t* utils_whex_to_uint8(const String &str)
{
    uint8_t c;
    int i;
    if (str.length() > TO_UINT8_HEX_BUF_LEN) {
        return NULL;
    }
    memset(buffer_whex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    for (i = 0; i < str.length() / 2; i++) {
        c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') {
            c += (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f') {
            c += (10 + str[i * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F') {
            c += (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
            c += (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f') {
            c += (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F') {
            c += (10 + str[i * 2 + 1] - 'A');
        }
        buffer_whex_to_uint8[i] = c;
    }
    return buffer_whex_to_uint8;
}

Error Bitcoin::load_seed(const String &seed_hex) {
	node_loaded = true;
  uint8_t *tmpbuf = utils_whex_to_uint8(seed_hex);
  memcpy(current_seed, tmpbuf, 16);
	btc_hdnode_from_seed(current_seed, 16, &node);

	return OK;
}

void Bitcoin::set_chain(const String &chain_name) {
	if (chain_name == "mainnet") {
		current_chainparams = &btc_chainparams_main;
    current_signed_message_prefix = String("\u0018Bitcoin Signed Message:\n");
	} else if (chain_name == "testnet") {
		current_chainparams = &btc_chainparams_test;
    current_signed_message_prefix = String("\u0018Bitcoin Signed Message:\n");
	} else if (chain_name == "regtest") {
		current_chainparams = &btc_chainparams_regtest;
    current_signed_message_prefix = String("\u0018Bitcoin Signed Message:\n");
	} else if (chain_name == "dash") {
		current_chainparams = &dash_chainparams_main;
    current_signed_message_prefix = String("\u0018Dash Signed Message:\n");
	} else if (chain_name == "mona") {
		current_chainparams = &mona_chainparams_main;
    current_signed_message_prefix = String("\u0018Monacoin Signed Message:\n");
	}
}

void print_hex(uint8_t *buf, int ln) {
  char hex[200];
  utils_bin_to_hex(buf, ln, hex);
  printf("-> %s\n", hex);
}

void print_privkey(uint8_t *buf) {
  char hex[BTC_ECKEY_PKEY_LENGTH * 2 + 1];
  utils_bin_to_hex(buf, BTC_ECKEY_PKEY_LENGTH, hex);
  printf("privkey -> %s\n", hex);
}

void print_pubkey(uint8_t *buf) {
  char hex[BTC_ECKEY_COMPRESSED_LENGTH * 2 + 1];
  utils_bin_to_hex(buf, BTC_ECKEY_COMPRESSED_LENGTH, hex);
  printf("pubkey -> %s\n", hex);
}

void Bitcoin::set_hd_path(const String &hd_path) {
	CharString asc_hd_path = hd_path.ascii();
  btc_hdnode_from_seed(current_seed, 16, &node);
  btc_hd_generate_key(&node, asc_hd_path.get_data(), node.private_key, node.chain_code, false);
}

String Bitcoin::get_p2pkh() {
	char str[112];
  btc_pubkey pk;
  for (int i=0; i < BTC_ECKEY_COMPRESSED_LENGTH; i++) {
    pk.pubkey[i] = node.public_key[i];
  }
  pk.compressed = true;

  btc_pubkey_getaddr_p2pkh(&pk, current_chainparams, str);

	return String(str);
}

int varuintEncodingLength(unsigned int v) {
  if (v < 0xfd) {
    return 1;
  } else if (v < 0xffff) {
    return 3;
  } else if (v  < 0xffffffff) {
    return 5;
  } else {
    return 9;
  }
}

void encodeVaruint(unsigned char *buf, unsigned int v) {
  if (v < 0xfd) {
    buf[0] = (char)(v & 0xFF);
  } else if (v < 0xffff) {
    buf[0] = 0xfd;
    buf[1] = (char)(v & 0xFF);
    buf[2] = (char)((v & 0xFF00) >> 8);
  } else if (v  < 0xffffffff) {
    buf[0] = 0xfe;
    buf[1] = (char)(v & 0xFF);
    buf[2] = (char)((v & 0xFF00) >> 8);
    buf[3] = (char)((v & 0xFF0000) >> 16);
    buf[4] = (char)((v & 0xFF000000) >> 24);
  } else {
    buf[0] = 0xff;
  }
}

Vector<uint8_t> Bitcoin::magic_hash(const String &p_message) {
  CharString msg = p_message.utf8();
  CharString msgPrefix = current_signed_message_prefix.utf8();

  unsigned int msgSize = msg.size() - 1;
  unsigned int prefixSize = msgPrefix.size() - 1;
  unsigned int vuilength = varuintEncodingLength(msgSize);

  unsigned int headerSize = vuilength + prefixSize;
  unsigned int totalSize = msgSize + headerSize;

  Vector<uint8_t> buf;
  buf.resize(totalSize);

  for (unsigned int i=0; i < prefixSize; i++) {
    buf.write[i] = msgPrefix.get(i);
  }

  encodeVaruint(&buf.write[prefixSize], msgSize);

  for (unsigned int i=0; i < msgSize; i++) {
    buf.write[headerSize + i] = msg.get(i);
  }

  Vector<uint8_t> hash;
  hash.resize(32);

  CryptoCore::SHA256Context sha256;
  sha256.start();
  sha256.update(&buf.write[0], totalSize);
  sha256.finish(&hash.write[0]);

  sha256.start();
  sha256.update(&hash.write[0], 32);
  sha256.finish(&hash.write[0]);

  return hash;
}

String Bitcoin::sign_message(const String &p_message) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_ecdsa_recoverable_signature rsig;
  unsigned char sig[64];
  int recid = 0;

  Vector<uint8_t> hash = magic_hash(p_message);
  secp256k1_ecdsa_sign_recoverable(ctx, &rsig, &hash.write[0], node.private_key, NULL, NULL);
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig, &recid, &rsig);

  secp256k1_context_destroy(ctx);

  PoolByteArray pba;
  pba.resize(65);
  pba.set(0, recid + 31);
  for (int i=0; i < 64; i++) {
    pba.set(i + 1, sig[i]);
  }

  _Marshalls m;
  return m.raw_to_base64(pba);
}

bool Bitcoin::verify_message(const String &p_message, const String &p_address, const String &p_signature) {
  _Marshalls m;
  PoolByteArray pba = m.base64_to_raw(p_signature);

  if (pba.size() == 65) {
    unsigned int flag = pba.get(0) - 27;
    int recid = flag & 3;
    Vector<uint8_t> hash = magic_hash(p_message);
    secp256k1_ecdsa_recoverable_signature rsig;
    secp256k1_pubkey recpubkey;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    for (int i=0; i < 64; i++) {
      recpubkey.data[i] = 0;
    }

    if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, &pba.write()[1], recid) == 1) {
      if (secp256k1_ecdsa_recover(ctx, &recpubkey, &rsig, &hash.write[0]) == 1) {
        // recpubkey tiene el pubkey antes de hash160 de la clave que firmo el mensaje
        unsigned char output[65];
        size_t output_length = 65;
        unsigned int flags = SECP256K1_EC_COMPRESSED;
        secp256k1_ec_pubkey_serialize(ctx, &output[0], &output_length, &recpubkey, flags);

        Vector<uint8_t> pubkeyhash;
        pubkeyhash.resize(34);
        int writtenBytes = btc_base58_decode_check(p_address.ascii().ptr(), &pubkeyhash.write[0], pubkeyhash.size());

        if (writtenBytes > 0) {
          uint256 hashout;
          sha256_Raw(output, output_length, hashout);
          btc_ripemd160(hashout, SHA256_DIGEST_LENGTH, hashout);

          return memcmp(&pubkeyhash.write[0], hashout, 20);
        } else {
          printf("Invalid address!\n");
          return false;
        }
      } else {
        printf("Couldnt recover signature!\n");
        return false;
      }
    } else {
      printf("Badly encoded signature!\n");
      return false;
    }

    secp256k1_context_destroy(ctx);
  } else {
    printf("Not enough data (must decode 65 bytes from base64, got %d)!\n", pba.size());
    return false;
  }
}

void Bitcoin::start_tx() {
  tx = btc_tx_new();
  value_in = 0;
  value_out = 0;
  amounts.clear();
}

void Bitcoin::add_input(const String &p_txid, uint32_t p_vout, int64_t p_value, const String &p_scriptsig) {
  btc_tx_in *txin = btc_tx_in_new();

  uint8_t *txid = utils_whex_to_uint8(p_txid);
  for (int i=0; i < 32; i++) {
    txin->prevout.hash[31 - i] = txid[i];
  }
  txin->prevout.n = p_vout;
  txin->sequence = 0xffffffff;

  uint8_t sighash[32];
  memset(sighash, 0, 32);


  cstring* script = cstr_new_buf(utils_whex_to_uint8(p_scriptsig), p_scriptsig.size() / 2);

  txin->script_sig = script;
  amounts.push_back(p_value);
  value_in += p_value;

  vector_add(tx->vin, txin);
}

bool Bitcoin::add_output_address_out(const String &p_address, int64_t p_value) {
  value_out += p_value;
  return btc_tx_add_address_out(tx, current_chainparams, p_value, p_address.ascii().ptr());
}

PoolByteArray Bitcoin::arc4_hexkey(PoolByteArray p_data, const String &p_key) {
  arc4_state st;
  uint8_t *key = utils_whex_to_uint8(p_key);
  arc4_init(&st, key, p_key.size()/2);
  PoolByteArray::Write w = p_data.write();
  arc4_crypt(&st, w.ptr(), p_data.size());
  PoolByteArray result;
  result.resize(p_data.size());

  for (int i=0; i < p_data.size(); i++) {
    result.set(i, w[i]);
  }

  return result;
}

PoolByteArray Bitcoin::arc4(PoolByteArray p_data, PoolByteArray p_key) {
  arc4_state st;
  arc4_init(&st, p_key.write().ptr(), p_key.size());
  PoolByteArray::Write w = p_data.write();
  arc4_crypt(&st, w.ptr(), p_data.size());
  PoolByteArray result;
  result.resize(p_data.size());

  for (int i=0; i < p_data.size(); i++) {
    result.set(i, w[i]);
  }

  return result;
}

PoolByteArray Bitcoin::decode_address(const String &p_address) {
  uint8_t data[64];

  int written = btc_base58_decode_check(p_address.ascii().ptr(), data, 64);

  PoolByteArray result;

  if (written >= 0) {
    result.resize(written);

    for (int i=0; i < written; i++) {
      result.set(i, data[i]);
    }
  }

  return result;
}

bool Bitcoin::add_output_data_out(PoolByteArray p_data, int64_t p_value) {
  value_out += p_value;

  return btc_tx_add_data_out(tx, p_value, p_data.write().ptr(), p_data.size());
}

bool Bitcoin::set_change(const String &p_address, int64_t p_feerate) {
  uint32_t expectedSize = tx->vin->len * 133 + tx->vout->len * 33 + 16;
  if (value_in > value_out) {
    uint64_t available = value_in - value_out;
    uint64_t expectedFee = p_feerate * expectedSize;

    if (expectedFee < MIN_RELAY_FEE) {
      expectedFee = MIN_RELAY_FEE;
    }

    if (available > expectedFee) {
      uint64_t expectedRemainAfterFee = available - expectedFee;

      if (expectedRemainAfterFee < DUST_LIMIT) {
        return true;
      } else {
        add_output_address_out(p_address, expectedRemainAfterFee);
        return true;
      }
    } else {
      return false;
    }
  } else {
    return false;
  }
  //return btc_tx_add_address_out(tx, current_chainparams, p_value, p_address.ascii().ptr());
}

int Bitcoin::sign_inputs(uint32_t inputindex) {
  if (inputindex < tx->vin->len) {
    uint8_t sigcomp[64] = {0};
    uint8_t sigder[76] = {0};
    int sigder_len = 0;
    btc_key pk;
    for (int i=0; i < BTC_ECKEY_PKEY_LENGTH; i++) {
      pk.privkey[i] = node.private_key[i];
    }

    int signResult = btc_tx_sign_input(
        tx, ((btc_tx_in*)(tx->vin->data[inputindex]))->script_sig,
        amounts.get(inputindex), &pk, inputindex, SIGHASH_ALL,
        sigcomp, sigder, &sigder_len);

    cstring *signedVin = ((btc_tx_in*)(tx->vin->data[inputindex]))->script_sig;
    cstring *partial = cstr_new_buf(&signedVin->str[25], signedVin->len - 25);
    ((btc_tx_in*)(tx->vin->data[inputindex]))->script_sig = partial;
    cstr_free(signedVin, true);

    return signResult;
  } else {
    return -1;
  }
}

String Bitcoin::build_tx() {
  cstring *s = cstr_new_sz(166);
  btc_tx_serialize(s, tx, true);

  char hexbuf[s->len*2+1];
  utils_bin_to_hex((unsigned char*)s->str, s->len, hexbuf);

  String result(hexbuf);
  cstr_free(s, true);

  return result;
}

String Bitcoin::get_tx_hash() {
  uint8_t hashout[32];

  btc_tx_hash(tx, hashout);

  char hex[65];
  utils_bin_to_hex(hashout, 32, hex);
  String result(hex);

  return result;
}

void Bitcoin::end_tx() {
  if (tx != NULL) {
    btc_tx_free(tx);
    tx = NULL;
  }
}*/

void Nebulas::gen_private_key() {
	int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

  do {
    mbedtls_ctr_drbg_random(&ctr_drbg, current_private_key, ECKEY_PKEY_LENGTH);
  } while (secp256k1_ec_seckey_verify(secp256k1_ctx, (const unsigned char*)current_private_key) == 0);
}

Error Nebulas::load_private_key(PoolByteArray p_data) {
  if (p_data.size() != 32) {
    return ERR_INVALID_DATA;
  }

  PoolByteArray::Write w = p_data.write();
  for (int i=0; i < p_data.size(); i++) {
    current_private_key[i] = w[i];
  }

  if (secp256k1_ec_seckey_verify(secp256k1_ctx, (const unsigned char*)current_private_key)) {
    return OK;
  } else {
    return ERR_INVALID_DATA;
  }
}

PoolByteArray Nebulas::get_private_key() {
  PoolByteArray p_data;
  p_data.resize(ECKEY_PKEY_LENGTH);
  PoolByteArray::Write w = p_data.write();
  for (int i=0; i < p_data.size(); i++) {
    w[i] = current_private_key[i];
  }

  return p_data;
}

void checksum(uint8_t* out, int outlen, uint8_t* data, int data_len) {
  uint8_t sha3_output[32];
  sha3_256(sha3_output, 32, data, data_len);

  for (int i=0; i < outlen; i++) {
    out[i] = sha3_output[i];
  }
}

String Nebulas::_get_address_by_type(uint8_t type, uint8_t* data, int data_len) {
  uint8_t addr_data[26];
  uint8_t sha3_output[32];
  addr_data[0] = PADDING_BYTE;
  addr_data[1] = type;

  sha3_256(sha3_output, 32, data, data_len);
  neb_ripemd160(sha3_output, 32, &addr_data[2]);
  checksum(&addr_data[21], 4, addr_data, 22);

  char b58res[70];
  size_t resSize = 70;
  neb_base58_encode(b58res, &resSize, addr_data, 26);
  return String(b58res);
}

/*String Bitcoin::get_p2pkh() {
	char str[112];
  btc_pubkey pk;
  for (int i=0; i < BTC_ECKEY_COMPRESSED_LENGTH; i++) {
    pk.pubkey[i] = node.public_key[i];
  }
  pk.compressed = true;

  btc_pubkey_getaddr_p2pkh(&pk, current_chainparams, str);

	return String(str);
}*/

String Nebulas::get_address() {
  return _get_address_by_type(ACCOUNT_BYTE, current_public_key, EC_PUBKEY_LENGTH);
}

void Nebulas::_bind_methods() {
  ClassDB::bind_method(D_METHOD("gen_private_key"), &Nebulas::gen_private_key);
  ClassDB::bind_method(D_METHOD("get_private_key"), &Nebulas::get_private_key);
  ClassDB::bind_method(D_METHOD("load_private_key", "p_data"), &Nebulas::load_private_key);
  ClassDB::bind_method(D_METHOD("get_address"), &Nebulas::get_address);
}

Nebulas::Nebulas() {
  secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
}

Nebulas::~Nebulas() {
  mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
  secp256k1_context_destroy(secp256k1_ctx);
  secp256k1_ctx = NULL;
}
