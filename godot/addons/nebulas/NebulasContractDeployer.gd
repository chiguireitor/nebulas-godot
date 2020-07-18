extends NebulasWallet
tool
class_name NebulasContractDeployer

signal deployment_complete

export(String) var address
export(String) var password setget _set_wallet_password, _get_wallet_password

var _current_warning = ''
var _current_password = ''

func editor_only(): # Needed to signal godot that this NebulasWallet descendant won't go live on production
	return true

func _ready():
	use_threads = true
	_current_warning = 'Change Password to open or create wallet'
	update_configuration_warning()
	if Engine.is_editor_hint():
		neb = Nebulas.new()

func _get_configuration_warning():
	return _current_warning

func _set_wallet_password(v):
	password = ''
	if OS.has_feature('editor') and len(v) > 6:
		wallet_path = "user://editor_wallet_nebulas.dat"
		var f = File.new()
		var key = _pin_to_key(v)
		if f.file_exists(wallet_path):
			if f.open_encrypted(wallet_path, File.READ, key) == OK:
				var hex = f.get_as_text()
				f.close()

				var p = 0
				var pba = PoolByteArray()
				for i in range(0, len(hex), 2):
					pba.append(("0x" + hex.substr(i, 2)).hex_to_int())
				if neb.load_private_key(pba) == OK:
					password = 'Wallet Opened'
					address = neb.get_address()
					_current_warning = ''
					_current_password = v
					update_configuration_warning()
					get_account_state()
				else:
					_current_warning = 'Wallet file damaged'
					update_configuration_warning()
			else:
				_current_warning = 'Password incorrect'
				update_configuration_warning()
		else:
			neb.gen_private_key()
			var pba = neb.get_private_key()
			var hex = pba.hex_encode()
			f.open_encrypted(wallet_path, File.WRITE, key)
			f.store_string(hex)
			f.close()
			address = neb.get_address()
			_current_warning = ''
			update_configuration_warning()

func _get_wallet_password():
	return ''

func find_transaction_object():
	for i in range(get_child_count()):
		var itm = get_child(i)

		if itm.has_signal("tx_result"):
			itm.from = get_address()
			itm.nonce = _last_account_state.nonce
			itm.wallet = self
			itm.gas_price = _current_gas_price
			itm.gas_limit = _current_gas_limit
			return itm
	return null

func deploy_contract(contract, args):
	if _current_password == null or len(_current_password) == 0:
		emit_signal("deployment_complete", { "error": "Deployer wallet not unlocked" })
		return

	load_wallet(_current_password)

	var t = find_transaction_object()

	if t == null:
		emit_signal("deployment_complete", { "error": "NebulasContractDeployer needs a NebulasTransaction as child to deploy contracts" })
		return

	t.to = get_address()
	t.value = 0
	t.contract = {
		"sourceType": "js",
		"source": contract,
		"args": JSON.print(args)
	}
	t.estimate_gas()
	var result = yield(t, 'tx_result')

	if result:
		t.contract = {
			"SourceType": "js",
			"Source": contract,
			"Args": JSON.print(args)
		}
		if t.send_tx(1):
			var tx_result: Dictionary = yield(t, 'tx_result')
			if tx_result.has("result") and tx_result.result.has("result"):
				var txhash =  tx_result.result.result.txhash
				var contract_address = tx_result.result.result.contract_address
				emit_signal("deployment_complete", { "contract_address": contract_address })
		else:
			emit_signal("deployment_complete", { "error": "Error while broadcasting transaction" })
	else:
		emit_signal("deployment_complete", { "error": "Couldn't estimate gas fees, " + t.estimation_error })

func _build_url_for_method(method: String):
	return _host + '/' + _api_version + '/' + _api_path + '/' + method
