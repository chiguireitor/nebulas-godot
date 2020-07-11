
#include "nebulas.h"

#include "core/crypto/crypto_core.h"
#include "core/bind/core_bind.h"
#include "core/os/os.h"

#include "keccak-tiny/keccak-tiny.h"
#include "libneb/ripemd160.h"
#include "libneb/base58.h"
#include "protobuf/transaction.pb.h"

bool Nebulas::_calc_pubkey() {
  return secp256k1_ec_pubkey_create(secp256k1_ctx, &current_public_key, current_private_key);
}

bool Nebulas::gen_private_key() {
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

  if (ret == 0) {
    do {
      mbedtls_ctr_drbg_random(&ctr_drbg, current_private_key, ECKEY_PKEY_LENGTH);
    } while (secp256k1_ec_seckey_verify(secp256k1_ctx, (const unsigned char*)current_private_key) == 0);

  	_calc_pubkey();
    use_temp_address = false;

    return true;
  } else {
    return false;
  }
}

bool Nebulas::gen_private_key_from_entropy(PoolByteArray pba) {
  if (pba.size() == 32) {
    uint8_t *data = pba.write().ptr();
    int ret = secp256k1_ec_seckey_verify(secp256k1_ctx, data);

    if (ret != 0) {
      memcpy(current_private_key, data, 32);
  	  _calc_pubkey();
      use_temp_address = false;

      return true;
    } else {
      return false;
    }
  } else {
    return false;
  }
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
		_calc_pubkey();
    use_temp_address = false;
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

void printhex(::std::string prev, uint8_t *data, int datalen) {
  PoolByteArray pba;
  pba.resize(datalen * 2 + 1);
  PoolByteArray::Write w = pba.write();
  char *p = (char *)w.ptr();

  for (int i=0; i < datalen; i++) {
    sprintf(&p[i * 2], "%02x", data[i]);
  }
  p[datalen * 2] = 0;

  OS::get_singleton()->print("%s %s\n", prev.c_str(), p);
}

void Nebulas::_get_address_bytes_by_type(uint8_t type, uint8_t* data, int data_len, uint8_t *addr_data, bool mangle) {
  uint8_t sha3_output[32];

  if (mangle) {
    secp256k1_pubkey temp_pubkey;
    memcpy(temp_pubkey.data, data, 64);
    uint8_t temp_ser[65];
    size_t temp_len = 65;

    secp256k1_ec_pubkey_serialize(secp256k1_ctx, temp_ser, &temp_len, &temp_pubkey, SECP256K1_EC_UNCOMPRESSED);

    sha3_256(sha3_output, 32, temp_ser, temp_len);
  } else {
    sha3_256(sha3_output, 32, data, data_len);
  }

  addr_data[0] = PADDING_BYTE;
  addr_data[1] = type;

  neb_ripemd160(sha3_output, 32, &addr_data[2]);
  checksum(&addr_data[22], 4, addr_data, 22);
}

String Nebulas::_get_address_by_type(uint8_t type, uint8_t* data, int data_len, bool mangle) {
  uint8_t addr_data[26];

	_get_address_bytes_by_type(type, data, data_len, addr_data, mangle);

  char b58res[70];
  size_t resSize = 70;
  neb_base58_encode(b58res, &resSize, addr_data, 26);
  return String(b58res);
}

String Nebulas::get_address() {
  if (use_temp_address) {
    return temp_address;
  } else {
    return _get_address_by_type(ACCOUNT_BYTE, current_public_key.data, EC_PUBKEY_LENGTH, true);
  }
}

uint32_t ul(const String &v) {
	return std::stoul(v.utf8().get_data());
}

uint64_t ull(const String &v) {
	return std::stoull(v.utf8().get_data());
}

void uint64_integer2bytes(uint64_t v, uint8_t *dest) {
	// 128bits
	for (int i=15; i >= 0; i--) {
		dest[i] = v % 256;
		v >>= 8;
	}
}

void uint64_long2bytes(uint64_t v, uint8_t *dest) {
	// 64bits
	for (int i=7; i >= 0; i--) {
		dest[i] = v % 256;
		v >>= 8;
	}
}

void uint64_int2bytes(uint64_t v, uint8_t *dest) {
	// 32bits
	for (int i=3; i >= 0; i--) {
		dest[i] = v % 256;
		v >>= 8;
	}
}

PoolByteArray Nebulas::send(const String &to, const String &value, uint64_t nonce) {
  String payload("");
  String payload_type("binary");

  return send_with_payload(to, value, nonce, payload, payload_type);
}

PoolByteArray Nebulas::send_with_payload(const String &to, const String &value, uint64_t nonce, const String &payload, const String &payload_type) {
  _calc_pubkey();
  PoolByteArray pba;
  if (use_temp_address == true) {
    pba = _send_with_payload_from_address(temp_address, to, value, nonce, payload, payload_type);
    use_temp_address = false;
  } else {
    pba = _send_with_payload_from_address(get_address(), to, value, nonce, payload, payload_type);
  }

  return pba;
}

void Nebulas::set_pub_address(const String &addr) {
  temp_address = addr;
  use_temp_address = true;
}

PoolByteArray Nebulas::_send_with_payload_from_address(const String &from, const String &to, const String &value, uint64_t nonce, const String &payload, const String &payload_type) {
  if (use_temp_address) {
    return PoolByteArray();
  }
  corepb::Transaction tx;

	uint8_t from_addr_data[26];
	uint8_t to_addr_data[26];
  //_calc_pubkey();
  //_get_address_bytes_by_type(ACCOUNT_BYTE, current_public_key.data, EC_PUBKEY_LENGTH, from_addr_data, true);
  size_t wsz = 26;
	char *base58data = from.utf8().ptrw();
	bool dec = neb_base58_decode(from_addr_data, &wsz, base58data);
  if (dec == 0) {
		// from_addr is an invalid address
    //printf("Invalid to address\n");
		return PoolByteArray();
	}

	wsz = 26;
	base58data = to.utf8().ptrw();
	dec = neb_base58_decode(to_addr_data, &wsz, base58data);
	if (dec == 0) {
		// to_addr is an invalid address
    //printf("Invalid to address\n");
		return PoolByteArray();
	}

	uint64_t timestamp = OS::get_singleton()->get_unix_time() * 1000;

	uint8_t value_data[16];
	uint8_t gas_price_data[16];
	uint8_t gas_limit_data[16];
	uint8_t timestamp_data[8];

	uint64_integer2bytes(ull(value), value_data);
	uint64_integer2bytes(ull(gas_price), gas_price_data);
	uint64_integer2bytes(ull(gas_limit), gas_limit_data);
	uint64_long2bytes(timestamp, timestamp_data);

	::std::string from_str((char *)from_addr_data, 26);
	::std::string to_str((char *)to_addr_data, 26);
	::std::string value_str((char *)value_data, 16);
	::std::string gas_price_str((char *)gas_price_data, 16);
	::std::string gas_limit_str((char *)gas_limit_data, 16);

	tx.set_chain_id(chain_id);
	tx.set_from(from_str);
	tx.set_to(to_str);
	tx.set_value(value_str);
	tx.set_gas_price(gas_price_str);
	tx.set_gas_limit(gas_limit_str);

	tx.set_nonce(nonce);
	tx.set_timestamp(timestamp);
	/*tx.mutable_data()->set_payload("");
	tx.mutable_data()->set_payload_type("binary");*/
  tx.mutable_data()->set_payload(payload.utf8().get_data());
	tx.mutable_data()->set_payload_type(payload_type.utf8().get_data());

  // Construct the buffer for transaction signature hash calculation
	size_t prebuf_sz = 84; // 2x address (26 bytes each), 1x 128bit int, 2x 64bit int
	size_t postbuf_sz = 36; // 1x 32bit int, 2x 128bit int
	::std::string data_ser;
	tx.data().SerializeToString(&data_ser);

	size_t payload_sz = data_ser.size();
	PoolByteArray tx_hashbuf;
	tx_hashbuf.resize(prebuf_sz + payload_sz + postbuf_sz);
	PoolByteArray::Write w = tx_hashbuf.write();
	memcpy(&w[0], from_addr_data, 26);
	memcpy(&w[26], to_addr_data, 26);

	memcpy(&w[52], value_data, 16);
	uint64_long2bytes(nonce, &w[68]);
	uint64_long2bytes(timestamp, &w[76]);

	// copy payload to &w[prebuf_sz]
	memcpy(&w[prebuf_sz], data_ser.c_str(), payload_sz);

	uint64_int2bytes(chain_id, &w[prebuf_sz + payload_sz]);
	memcpy(&w[prebuf_sz + payload_sz + 4], gas_price_data, 16);
	memcpy(&w[prebuf_sz + payload_sz + 20], gas_limit_data, 16);

  // Calculate the transaction hash
	uint8_t sha3_output[32];
  sha3_256(sha3_output, 32, &w[0], tx_hashbuf.size());

	::std::string hash((char *)sha3_output, 32);
	tx.set_hash(hash);

  // Sign the transaction hash
	secp256k1_ecdsa_recoverable_signature sig;
  int sign_result = secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, sha3_output, current_private_key, secp256k1_nonce_function_rfc6979, NULL);
  if (sign_result == 0) {
    //printf("the nonce generation function failed, or the private key was invalid\n");
    return PoolByteArray();
  }
	uint8_t sig_data[65];

  int recid = 0;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, &sig_data[0], &recid, &sig);
  sig_data[64] = (uint8_t)(recid & 0xFF);

	::std::string sign((char *)sig_data, 65);
	tx.set_sign(sign);

	tx.set_alg(ALG_SECP256K1);

	::std::string outp;
	tx.SerializeToString(&outp);

	PoolByteArray pba;
	pba.resize(outp.size());
	const char *pt = outp.c_str();
	for (size_t i=0; i < outp.size(); i++) {
		pba.set(i, pt[i]);
	}

	return pba;
}

void Nebulas::set_gas_price(const String &new_gas_price) {
	gas_price = new_gas_price;
}

String Nebulas::get_gas_price() {
	return gas_price;
}

void Nebulas::set_gas_limit(const String &new_gas_limit) {
	gas_limit = new_gas_limit;
}

String Nebulas::get_gas_limit() {
	return gas_limit;
}

void Nebulas::_bind_methods() {
  ClassDB::bind_method(D_METHOD("gen_private_key"), &Nebulas::gen_private_key);
  ClassDB::bind_method(D_METHOD("gen_private_key_from_entropy", "p_data"), &Nebulas::gen_private_key_from_entropy);
  ClassDB::bind_method(D_METHOD("get_private_key"), &Nebulas::get_private_key);
  ClassDB::bind_method(D_METHOD("load_private_key", "p_data"), &Nebulas::load_private_key);
  ClassDB::bind_method(D_METHOD("get_address"), &Nebulas::get_address);
	ClassDB::bind_method(D_METHOD("send", "to", "value", "nonce"), &Nebulas::send);
  ClassDB::bind_method(D_METHOD("send_with_payload", "to", "value", "nonce", "payload", "payload_type"), &Nebulas::send_with_payload);
  ClassDB::bind_method(D_METHOD("set_pub_address", "addr"), &Nebulas::set_pub_address);

	ClassDB::bind_method(D_METHOD("set_gas_price", "gas_price"), &Nebulas::set_gas_price);
	ClassDB::bind_method(D_METHOD("get_gas_price"), &Nebulas::get_gas_price);
	ClassDB::bind_method(D_METHOD("set_gas_limit", "gas_limit"), &Nebulas::set_gas_limit);
	ClassDB::bind_method(D_METHOD("get_gas_limit"), &Nebulas::get_gas_limit);

	ADD_PROPERTY(PropertyInfo(Variant::STRING, "gas_price", PROPERTY_HINT_TYPE_STRING), "set_gas_price", "get_gas_price");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "gas_limit", PROPERTY_HINT_TYPE_STRING), "set_gas_limit", "get_gas_limit");
}

Nebulas::Nebulas() {
	GOOGLE_PROTOBUF_VERIFY_VERSION;

  secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	chain_id = 1001;
	alg = 1;
  use_temp_address = false;
}

Nebulas::~Nebulas() {
  mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
  secp256k1_context_destroy(secp256k1_ctx);
  secp256k1_ctx = NULL;

	google::protobuf::ShutdownProtobufLibrary();
}
