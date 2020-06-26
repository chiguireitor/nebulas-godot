#include "register_types.h"
//#include "core/error_macros.h"
#include "nebulas.h"
//#include "btc/ecc.h"

void register_nebulas_types() {
	//btc_ecc_start();

	ClassDB::register_class<Nebulas>();
}

void unregister_nebulas_types() {
	//btc_ecc_stop();
}
