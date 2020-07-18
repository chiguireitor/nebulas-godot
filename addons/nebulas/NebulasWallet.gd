extends HTTPRequest

class_name NebulasWallet

signal account_state(result)
signal address_info(result)
signal estimate_gas(result)
signal gas_price(result)
signal broadcast_tx(result)
signal call_contract(result)

signal new_nrc20(token)
signal new_nrc721(token)

const default_wallet_path = "user://wallet_nebulas.dat"
onready var neb = Nebulas.new()

const _explorer_mainnet = 'https://data.nebulas.io/api'
const _explorer_testnet = 'https://explorer-test-backend.nebulas.io/api'
const _api_mainnet = 'https://mainnet.nebulas.io'
const _api_testnet = 'https://testnet.nebulas.io'

# https://testnet.nebulas.io/     v1      /    user    /    nebstate
#         |      host       |   version   |    path    |     method

var wallet_path = default_wallet_path
var _host = _api_testnet
var _explorer = _explorer_testnet
var _api_version = 'v1'
var _api_path = 'user'
var _network = 'testnet'
var _http_api: HTTPRequest
var _http_exp: HTTPRequest
var _last_account_state = null
var _current_gas_price = 0
var _current_gas_limit = 50000000000
var initialized = true

var _known_nrc20s = {}
var _known_nrc721s = {}
var _nft_by_name = {}

var _api_handler_signal = {}
var _timer_update: Timer
var _wallet_ui_send = null

var updating_nrc721s = false

func register_nrc20(token):
	_known_nrc20s[token.token_symbol] = token
	emit_signal("new_nrc20", token)

func register_nrc721(token):
	_known_nrc721s[token.address] = token
	emit_signal("new_nrc721", token)
	start_update_timeout()

func register_nft(nft):
	if !_nft_by_name.has(nft.name):
		_nft_by_name[nft.name] = {"watchers": [], "token": nft}
	call_nft_watchers(nft)

func register_wallet_ui_send(cb):
	_wallet_ui_send = cb

func invoke_ui_send(token, amount=0):
	if _wallet_ui_send != null:
		_wallet_ui_send.call_func(token, amount)
		return true
	else:
		return false

func watch_nft_by_name(name, cb):
	if !_nft_by_name.has(name):
		_nft_by_name[name] = {"watchers": [], "token": null}
	_nft_by_name[name].watchers.append(cb)
	if _nft_by_name[name].token != null:
		cb.call_func(_nft_by_name[name].token)

func call_nft_watchers(token):
	for w in _nft_by_name[token.name].watchers:
		w.call_func(token)

func get_nrc20s():
	return _known_nrc20s.keys()

func get_nrc721s():
	return _known_nrc721s.keys()

func get_token_by_name(name):
	if _nft_by_name.has(name) and _nft_by_name[name].token != null:
		return _nft_by_name[name].token
	else:
		return null

func start_update_timeout():
	if _timer_update != null:
		_timer_update.stop()
		_timer_update.start(0.5)

func update_balances():
	update_nrc721s_balances()

func update_nrc721s_balances():
	if updating_nrc721s:
		return

	updating_nrc721s = true
	for token_address in _known_nrc721s:
		var token = _known_nrc721s[token_address]

		for i in range(token.get_child_count()):
			var child = token.get_child(i)

			if child.has_method("_update_balance"):
				child._update_balance()
				yield(child, "balance_updated")
				call_nft_watchers(child)
	updating_nrc721s = false

func get_token(tk_name):
	if _known_nrc20s.has(tk_name):
		return _known_nrc20s[tk_name]

	if _known_nrc721s.has(tk_name):
		return _known_nrc721s[tk_name]

	return null

func get_token_by_address(addr):
	for x in _known_nrc20s:
		var tok = _known_nrc20s[x]
		if addr == tok.address:
			return tok

	for x in _known_nrc721s:
		var tok = _known_nrc721s[x]
		if addr == tok.address:
			return tok
	return null

func _ready():
	if !has_method('editor_only'):
		_http_api = HTTPRequest.new()
		_http_api.use_threads = true
		add_child(_http_api)
		_http_api.connect("request_completed", self, "_get_api_completed", ["api"])

		_http_exp = HTTPRequest.new()
		_http_exp.use_threads = true
		add_child(_http_exp)
		_http_exp.connect("request_completed", self, "_get_api_completed", ["exp"])

		_timer_update = Timer.new()
		_timer_update.one_shot = true
		_timer_update.connect("timeout", self, "update_balances")
		add_child(_timer_update)

		var f = File.new()
		if f.file_exists(wallet_path + '.pub'):
			f.open(wallet_path + '.pub', File.READ)
			var addr = f.get_as_text()
			if len(addr) == 35:
				neb.set_pub_address(addr)
				f.close()
				start_update_timeout()

		get_gas_price()
	elif Engine.is_editor_hint():
		_http_api = self
		_api_handler_signal = {}
		connect("request_completed", self, "_get_api_completed", ["api"])
		get_gas_price()

func new_transaction():
	if _last_account_state == null:
		return null

	var nt = NebulasTransaction.new()
	nt.from = get_address()
	nt.nonce = _last_account_state.nonce
	nt.wallet = self
	nt.gas_price = _current_gas_price
	nt.gas_limit = _current_gas_limit

	add_child(nt)

	return nt

func set_api(host_url: String, version: String = 'v1'):
	_host = host_url
	_api_version = version

func _build_url_for_method(method: String):
	return _host + '/' + _api_version + '/' + _api_path + '/' + method

func build_url_for_method(method: String):
	return _build_url_for_method(method)

func get_current_gas_limit():
	return _current_gas_limit

func get_current_gas_price():
	return _current_gas_price

func num_to_printable(n, decs=18):
	var num = float(n) / float("1" + "0".repeat(decs))
	return str(num)

func printable_to_num(n: String, decs=18):
	var parts = n.split('.')
	if len(parts) == 1:
		return int(str(parts[0]) + "0".repeat(decs))
	else:
		var res = str(parts[0])
		var dec_str: String = parts[1]
		var res_dec = ''
		while dec_str[0] == "0":
			res_dec += '0'
			dec_str = dec_str.substr(1)
		if len(dec_str) > 0:
			res_dec += str(dec_str)
		while len(res_dec) < decs:
			res_dec += '0'
		return int(res + res_dec)

func wallet_exists():
	var f = File.new()
	return f.file_exists(wallet_path)

func _pin_to_key(pin: String):
	var salt = 'nebulas_salt'
	return ((pin + salt).sha256_buffer().hex_encode() + salt).sha256_buffer()

func new_wallet(pin: String):
	if neb.gen_private_key():
		finish_creating_new_wallet(pin)
		return true
	else:
		var cr = Crypto.new()
		var pba = cr.generate_random_bytes(32)
		var success = neb.gen_private_key_from_entropy(pba)
		var tries = 50

		while tries > 0 and !success:
			tries -= 1
			success = neb.gen_private_key_from_entropy(pba)

		if success:
			finish_creating_new_wallet(pin)

		return success

func get_private_key():
	var pba = neb.get_private_key()
	return pba.hex_encode()

func finish_creating_new_wallet(pin):
	var pba = neb.get_private_key()
	var hex = pba.hex_encode()
	var f = File.new()
	var key = _pin_to_key(pin)
	f.open_encrypted(wallet_path, File.WRITE, key)
	f.store_string(hex)
	f.close()

	f.open(wallet_path + '.pub', File.WRITE)
	f.store_string(neb.get_address())
	f.close()
	initialized = true

func load_wallet(pin: String):
	initialized = false
	var key = _pin_to_key(pin)
	var f = File.new()
	if f.open_encrypted(wallet_path, File.READ, key) == OK:
		var hex = f.get_as_text()
		f.close()

		var p = 0
		var pba = PoolByteArray()
		for i in range(0, len(hex), 2):
			pba.append(("0x" + hex.substr(i, 2)).hex_to_int())
		if neb.load_private_key(pba) == OK:
			initialized = true
			f.open(wallet_path + '.pub', File.WRITE)
			f.store_string(neb.get_address())
			f.close()
			return pba
		else:
			return null
	else:
		return null

func get_address():
	var addr = neb.get_address()
	return addr

func get_account_state(height: int = 0):
	if _api_handler_signal.has("api"):
		yield(self, _api_handler_signal["api"])

	var url = _build_url_for_method('accountstate')
	var params = {
		"address": get_address(),
		"height": height
	}
	var headers = ["Content-Type: application/json"]
	_api_handler_signal["api"] = "account_state"
	_http_api.request(url, headers, true, HTTPClient.METHOD_POST, JSON.print(params))
	return self

func _trap_account_state(data):
	_last_account_state = data.result

func rawtransaction(pba: PoolByteArray):
	if _api_handler_signal.has("api"):
		yield(self, _api_handler_signal["api"])

	var url = _build_url_for_method('rawtransaction')
	var params = {
		"data": Marshalls.raw_to_base64(pba)
	}
	print(params)
	var headers = ["Content-Type: application/json"]
	_api_handler_signal["api"] = "broadcast_tx"
	_http_api.request(url, headers, true, HTTPClient.METHOD_POST, JSON.print(params))
	return self

func estimate_gas(params):
	if _api_handler_signal.has("api"):
		yield(self, _api_handler_signal["api"])

	var url = _build_url_for_method('estimateGas')
	var headers = ["Content-Type: application/json"]
	_api_handler_signal["api"] = "estimate_gas"
	_http_api.request(url, headers, true, HTTPClient.METHOD_POST, JSON.print(params))
	return self

func call_contract(params):
	if _api_handler_signal.has("api"):
		yield(self, _api_handler_signal["api"])

	var url = _build_url_for_method('call')
	var headers = ["Content-Type: application/json"]
	_api_handler_signal["api"] = "call_contract"
	_http_api.request(url, headers, true, HTTPClient.METHOD_POST, JSON.print(params))
	return self

func get_gas_price():
	if _api_handler_signal.has("api"):
		yield(self, _api_handler_signal["api"])

	var url = _build_url_for_method('getGasPrice')
	_api_handler_signal["api"] = "gas_price"
	_http_api.request(url)
	return self

func _trap_gas_price(res):
	if res.has('result'):
		_current_gas_price = res.result.gas_price

func get_address_info():
	if _api_handler_signal.has("exp"):
		yield(self, _api_handler_signal["exp"])

	var url = _explorer + '/address/' + get_address()
	_api_handler_signal["exp"] = "address_info"
	_http_exp.request(url)
	return self

func _get_api_completed(result, response_code, headers, body: PoolByteArray, origin):
	var utf = body.get_string_from_utf8()
	var expected_signal = _api_handler_signal[origin]
	_api_handler_signal.erase(origin)

	if response_code == 200:
		var ob = JSON.parse(utf)
		if ob.error == OK:
			if self.has_method("_trap_" + expected_signal):
				self.call("_trap_" + expected_signal, ob.result)

			emit_signal(expected_signal, {"result": ob.result})
		else:
			emit_signal(expected_signal, {"error": {"code": ob.error_string, "body": utf}})
	else:
		emit_signal(expected_signal, {"error": {"code": response_code, "body": utf}})
