extends HTTPRequest
tool
class_name NebulasContractNRC20

signal http_finished_normalized(result)

enum NETWORK { mainnet, testnet }

export(String) var address setget _address_set
export(NETWORK) var network = NETWORK.testnet setget _network_set
export(String) var token_name
export(String) var token_symbol
export(int) var token_decimals
export(String) var token_total_supply

export(bool) var deploy setget _deploy_set, _deploy_get

var current_gas = 0

var GAS_PRICE_MAX = 1000000000000
var GAS_LIMIT_MAX = 50000000000

var _current_warning = ''
var _is_deploying = false

func _get_configuration_warning():
	return _current_warning

func _ready():
	use_threads = true
	connect("request_completed", self, "api_http_request_completed")
	_update_contract()

func _deploy_set(v):
	if v and Engine.is_editor_hint():
		var prnt = get_parent()
		_current_warning = ''
		var problems = PoolStringArray()
		
		if _is_deploying:
			problems.append('Currently deploying')
		if len(address) > 0:
			problems.append('Already deployed')
		if !prnt.has_method("deploy_contract"):
			problems.append('Parent must be a NebulasContractDeployer')
		if len(token_name) == 0:
			problems.append('Name not set')
		if len(token_symbol) == 0:
			problems.append('Symbol not set')
		if !(token_decimals >= 0 and token_decimals <= 18):
			problems.append('Decimals must be between 0 and 18 inclusive')
		if len(token_total_supply) == 0:
			problems.append('invalid token supply')
		elif !_valid_bignum(token_total_supply):
			problems.append('invalid token supply')
		if len(problems) > 0:
			_current_warning = problems.join(', ') + ', you cannot deploy this contract'
			
		update_configuration_warning()
		if _current_warning == '':
			_is_deploying = true
			prnt.deploy_contract(standard_nrc20_contract, [token_name, token_symbol, token_decimals, token_total_supply])
			prnt.connect('deployment_complete', self, '_finish_deployment', [], CONNECT_ONESHOT)

func _finish_deployment(result):
	_current_warning = ''
	_is_deploying = false

	if result.has('contract_address'):
		address = result.contract_address
	else:
		_current_warning = result.error
	
	update_configuration_warning()

func _valid_bignum(v):
	var r = v.split('.')
	if len(r) > 2:
		return false
	else:
		return int(r[0]) != 0 or int(r[1]) != 0
	
func _deploy_get():
	return false

func api_http_request_completed(result, response_code, headers, body: PoolByteArray):
	var utf = body.get_string_from_utf8()
	if response_code == 200:
		var ob = JSON.parse(utf)
		if ob.error == OK:
			emit_signal("http_finished_normalized", {"result": ob.result.result})
		else:
			emit_signal("http_finished_normalized", {"error": {"code": ob.error_string, "body": utf}})
	else:
		emit_signal("http_finished_normalized", {"error": {"code": response_code, "body": utf}})

func _address_set(naddr: String):
	if address != naddr:
		address = naddr
		_update_contract()

func _network_set(nnet):
	if network != nnet:
		network = nnet
		_update_contract()

func network_as_name(n: int) -> String:
	match n:
		NETWORK.mainnet:
			return "mainnet"
		NETWORK.testnet:
			return "testnet"
	return "unknown"

var loaded = null
func _update_contract():
	var f = File.new()
	var fname = "user://nrc20_" + network_as_name(network) + "_" + address + ".json"

	if loaded != fname and f.file_exists(fname):
		f.open(fname, File.READ)
		var res: JSONParseResult = JSON.parse(f.get_as_text())
		f.close()
		
		if res.error == OK:
			loaded = fname
			token_name = res.result.name
			token_symbol = res.result.symbol
			token_decimals = res.result.decimals
			token_total_supply = res.result.total_supply
			if NebulasWalletSingleton != null and !Engine.is_editor_hint():
				NebulasWalletSingleton.register_nrc20(self)

	if NebulasWalletSingleton == null:
		return
	
	if loaded != fname and is_inside_tree() and !Engine.is_editor_hint():
		if NebulasWalletSingleton != null and NebulasWalletSingleton.initialized:
			if address != null and len(address) == 35 and address.begins_with("n"):
				_call_ro_contract_function("name", [])
				var name_result = yield(self, "http_finished_normalized")
				if name_result.has("result"):
					token_name = JSON.parse(name_result.result.result).result
				else:
					return
					
				_call_ro_contract_function("symbol", [])
				var symbol_result = yield(self, "http_finished_normalized")
				if symbol_result.has("result"):
					token_symbol = JSON.parse(symbol_result.result.result).result
				else:
					return
					
				_call_ro_contract_function("decimals", [])
				var decimals_result = yield(self, "http_finished_normalized")
				if decimals_result.has("result"):
					token_decimals = int(JSON.parse(decimals_result.result.result).result)
				else:
					return
					
				_call_ro_contract_function("totalSupply", [])
				var supply_result = yield(self, "http_finished_normalized")
				if supply_result.has("result"):
					token_total_supply = JSON.parse(supply_result.result.result).result
				else:
					return
					
				NebulasWalletSingleton.register_nrc20(self)
				f.open(fname, File.WRITE)
				f.store_string(JSON.print({
					"name": token_name,
					"symbol": token_symbol,
					"decimals": token_decimals,
					"total_supply": token_total_supply
				}))
				f.close()
				loaded = fname
			
func _call_ro_contract_function(contract_function, contract_args):
	var url = NebulasWalletSingleton.build_url_for_method('call')
	var source_address = address # Doesn't needs to be our own address, it's read-only anyways and we don't care the execution result
	var headers = ["Content-Type: application/json"]
	var params = {
		"gasLimit": '1',
		"gasPrice": '1',
		"nonce": 0, # nonce doesn't matter for readonly calls
		"value": "0",
		"to": address,
		"from": source_address,
		"contract": {
			"args": JSON.print(contract_args),
			"function": contract_function
		}
	}
	var ret = request(url, headers, true, HTTPClient.METHOD_POST, JSON.print(params))
	
func create_send(tx, to: String, value: String):
	tx.to = address
	tx.value = 0
	tx.contract_call = {
		"Function": "transfer",
		"Args": JSON.print([to, value])
	}
	#tx.

const standard_nrc20_contract = """
'use strict';

let Allowed = function (obj) {
	this._allowed = {};
	this.parse(obj);
};

Allowed.prototype = {
	toString: function () {
		return JSON.stringify(this._allowed);
	},

	parse: function (obj) {
		if (typeof obj != "undefined") {
			let data = JSON.parse(obj);
			for (let key in data) {
				this._allowed[key] = new BigNumber(data[key]);
			}
		}
	},

	get: function (key) {
		return this._allowed[key];
	},

	set: function (key, value) {
		this._allowed[key] = new BigNumber(value);
	}
};

let StandardToken = function () {
	LocalContractStorage.defineProperties(this, {
		_name: null,
		_symbol: null,
		_decimals: null,
		_totalSupply: {
			parse: function (value) {
				return new BigNumber(value);
			},
			stringify: function (o) {
				return o.toString(10);
			}
		}
	});

	LocalContractStorage.defineMapProperties(this, {
		"_balances": {
			parse: function (value) {
				return new BigNumber(value);
			},
			stringify: function (o) {
				return o.toString(10);
			}
		},
		"_allowed": {
			parse: function (value) {
				return new Allowed(value);
			},
			stringify: function (o) {
				return o.toString();
			}
		}
	});
};

StandardToken.prototype = {
	init: function (name, symbol, decimals, totalSupply) {
		this._name = name;
		this._symbol = symbol;
		this._decimals = decimals || 0;
		this._totalSupply = new BigNumber(totalSupply).mul(new BigNumber(10).pow(decimals));

		let from = Blockchain.transaction.from;
		this._balances.set(from, this._totalSupply);
		this._transferEvent(true, from, from, this._totalSupply);
	},

	// Returns the name of the token
	name: function () {
		return this._name;
	},

	// Returns the symbol of the token
	symbol: function () {
		return this._symbol;
	},

	// Returns the number of decimals the token uses
	decimals: function () {
		return this._decimals;
	},

	totalSupply: function () {
		return this._totalSupply.toString(10);
	},

	balanceOf: function (owner) {
		this._verifyAddress(owner);

		let balance = this._balances.get(owner);
		if (balance instanceof BigNumber) {
			return balance.toString(10);
		} else {
			return "0";
		}
	},
	_verifyAddress: function (address) {
		if (Blockchain.verifyAddress(address) === 0) {
			throw new Error("Address format error, address=" + address);
		}
	},

	_verifyValue: function(value) {
		let bigVal = new BigNumber(value);
		if (bigVal.isNaN() || !bigVal.isFinite()) {
			throw new Error("Invalid value, value=" + value);
		}
		if (bigVal.isNegative()) {
			throw new Error("Value is negative, value=" + value);
		}
		if (!bigVal.isInteger()) {
			throw new Error("Value is not integer, value=" + value);
		}
		if (value !== bigVal.toString(10)) {
			throw new Error("Invalid value format.");
		}
	},

	transfer: function (to, value) {
		this._verifyAddress(to);
		this._verifyValue(value);

		value = new BigNumber(value);
		let from = Blockchain.transaction.from;
		let balance = this._balances.get(from) || new BigNumber(0);

		if (balance.lt(value)) {
			throw new Error("transfer failed.");
		}

		this._balances.set(from, balance.sub(value));
		let toBalance = this._balances.get(to) || new BigNumber(0);
		this._balances.set(to, toBalance.add(value));

		this._transferEvent(true, from, to, value.toString(10));
	},

	transferFrom: function (from, to, value) {
		this._verifyAddress(from);
		this._verifyAddress(to);
		this._verifyValue(value);

		let spender = Blockchain.transaction.from;
		let balance = this._balances.get(from) || new BigNumber(0);

		let allowed = this._allowed.get(from) || new Allowed();
		let allowedValue = allowed.get(spender) || new BigNumber(0);
		value = new BigNumber(value);

		if (balance.gte(value) && allowedValue.gte(value)) {

			this._balances.set(from, balance.sub(value));

			// update allowed value
			allowed.set(spender, allowedValue.sub(value));
			this._allowed.set(from, allowed);

			let toBalance = this._balances.get(to) || new BigNumber(0);
			this._balances.set(to, toBalance.add(value));

			this._transferEvent(true, from, to, value.toString(10));
		} else {
			throw new Error("transfer failed.");
		}
	},

	_transferEvent: function (status, from, to, value) {
		Event.Trigger(this.name(), {
			Status: status,
			Transfer: {
				from: from,
				to: to,
				value: value
			}
		});
	},

	approve: function (spender, currentValue, value) {
		this._verifyAddress(spender);
		this._verifyValue(currentValue);
		this._verifyValue(value);

		let from = Blockchain.transaction.from;

		let oldValue = this.allowance(from, spender);
		if (oldValue != currentValue) {
			throw new Error("current approve value mistake.");
		}

		let balance = new BigNumber(this.balanceOf(from));
		value = new BigNumber(value);

		if (balance.lt(value)) {
			throw new Error("invalid value.");
		}

		let owned = this._allowed.get(from) || new Allowed();
		owned.set(spender, value);

		this._allowed.set(from, owned);

		this._approveEvent(true, from, spender, value.toString(10));
	},

	_approveEvent: function (status, from, spender, value) {
		Event.Trigger(this.name(), {
			Status: status,
			Approve: {
				owner: from,
				spender: spender,
				value: value
			}
		});
	},

	allowance: function (owner, spender) {
		this._verifyAddress(owner);
		this._verifyAddress(spender);

		let owned = this._allowed.get(owner);
		if (owned instanceof Allowed) {
			let spenderObj = owned.get(spender);
			if (typeof spenderObj != "undefined") {
				return spenderObj.toString(10);
			}
		}
		return "0";
	}
};

module.exports = StandardToken;
"""
