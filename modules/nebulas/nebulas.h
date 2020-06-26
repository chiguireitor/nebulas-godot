#ifndef NEBULAS_H
#define NEBULAS_H

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "core/reference.h"
#include "core/variant.h"

#include "secp256k1.h"

/*#include <btc/utils.h>
#include <btc/bip32.h>
#include <btc/tx.h>*/

#define PADDING_BYTE 0x19
#define ACCOUNT_BYTE 0x57
#define CONTRACT_BYTE 0x58

#define ECKEY_PKEY_LENGTH 32
#define EC_PUBKEY_LENGTH 32

class Nebulas : public Reference  {

	GDCLASS(Nebulas, Reference);

public:

private:
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	secp256k1_context* secp256k1_ctx;
	uint8_t current_private_key[ECKEY_PKEY_LENGTH];
	uint8_t current_public_key[EC_PUBKEY_LENGTH];
	/*bool node_loaded;
	String current_signed_message_prefix;
	btc_hdnode node;
	uint8_t current_seed[16];
	btc_tx *tx;
	int64_t value_in;
	int64_t value_out;
	int64_t current_fee_per_sat;
	const btc_chainparams *current_chainparams;

	Vector<uint8_t> magic_hash(const String &p_message);
	Vector<uint64_t> amounts;*/

	String _get_address_by_type(uint8_t type, uint8_t* data, int data_len);

protected:
	static void _bind_methods();

public:
	void gen_private_key();
	PoolByteArray get_private_key();
	Error load_private_key(PoolByteArray p_data);
	String get_address();

	/*Error load_seed(const String &seed_hex);
	void set_chain(const String &chain_name);
	void set_hd_path(const String &hd_path);
	String get_p2pkh();

	void start_tx();
	void add_input(const String &p_txid, uint32_t p_vout, int64_t p_value, const String &p_scriptsig);
	bool add_output_address_out(const String &p_address, int64_t p_value);
	bool add_output_data_out(PoolByteArray p_data, int64_t p_value);
	int sign_inputs(uint32_t inputindex);
	String build_tx();
	String get_tx_hash();
	void end_tx();
	bool set_change(const String &p_address, int64_t p_feerate);

	PoolByteArray arc4(PoolByteArray p_data, PoolByteArray p_key);
	PoolByteArray arc4_hexkey(PoolByteArray p_data, const String &p_key);
	PoolByteArray decode_address(const String &p_address);

	String sign_message(const String &p_message);
	bool verify_message(const String &p_message, const String &p_address, const String &p_signature);*/

	Nebulas();
	~Nebulas();
};

#endif // NEBULAS_H
