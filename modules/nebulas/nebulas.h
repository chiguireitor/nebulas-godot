#ifndef NEBULAS_H
#define NEBULAS_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#ifndef NEBULAS_GDNATIVE
#include "core/reference.h"
#include "core/variant.h"
#endif

#ifdef NEBULAS_GDNATIVE
#include <Godot.hpp>
#include <Reference.hpp>
#include <Variant.hpp>
#endif

#include "secp256k1.h"
#include "secp256k1_recovery.h"

#define PADDING_BYTE 0x19
#define ACCOUNT_BYTE 0x57
#define CONTRACT_BYTE 0x58

#define ECKEY_PKEY_LENGTH 32
#define EC_PUBKEY_LENGTH 64

#define ALG_SECP256K1 1

class Nebulas : public Reference  {

	GDCLASS(Nebulas, Reference);

public:

private:
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	secp256k1_context* secp256k1_ctx;
	uint8_t current_private_key[ECKEY_PKEY_LENGTH];
	secp256k1_pubkey current_public_key;

	// For transaction building
	uint32_t chain_id, alg;
	String gas_price, gas_limit;
	String temp_address;
	bool use_temp_address;

	void _get_address_bytes_by_type(uint8_t type, uint8_t* data, int data_len, uint8_t *addr_data, bool mangle);
	String _get_address_by_type(uint8_t type, uint8_t* data, int data_len, bool mangle);
	bool _calc_pubkey();
	PoolByteArray _send_with_payload_from_address(const String &from, const String &to, const String &value, uint64_t nonce, const String &payload, const String &payload_type);
protected:
	#ifndef NEBULAS_GDNATIVE
	static void _bind_methods();
	#endif

	#ifdef NEBULAS_GDNATIVE
	static void _register_methods();
	#endif

public:
	bool gen_private_key();
	bool gen_private_key_from_entropy(PoolByteArray pba);
	PoolByteArray get_private_key();
	Error load_private_key(PoolByteArray p_data);
	String get_address();
	PoolByteArray send(const String &to, const String &value, uint64_t nonce);
	PoolByteArray send_with_payload(const String &to, const String &value, uint64_t nonce, const String &payload, const String &payload_type);
	void set_pub_address(const String &addr);

	void set_gas_price(const String &new_gas_price);
	String get_gas_price();
	void set_gas_limit(const String &new_gas_limit);
	String get_gas_limit();

	Nebulas();
	~Nebulas();
};

#endif // NEBULAS_H
