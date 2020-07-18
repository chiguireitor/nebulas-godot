extends HTTPRequest
tool
class_name NebulasContractNRC721

signal http_finished_normalized(result)
signal mint_result(result)
signal transfer_result(result)

enum NETWORK { mainnet, testnet }

export(String) var address setget _address_set
export(NETWORK) var network = NETWORK.testnet setget _network_set
export(String) var token_name

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
		if len(problems) > 0:
			_current_warning = problems.join(', ') + ', you cannot deploy this contract'
			
		update_configuration_warning()
		if _current_warning == '':
			_is_deploying = true
			prnt.deploy_contract(standard_nrc721_contract, [token_name])
			prnt.connect('deployment_complete', self, '_finish_deployment', [], CONNECT_ONESHOT)

func _finish_deployment(result):
	_current_warning = ''
	_is_deploying = false

	if result.has('contract_address'):
		address = result.contract_address
	else:
		_current_warning = result.error
	
	update_configuration_warning()
	
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

func nft_by_id(id):
	for i in range(get_child_count()):
		var itm = get_child(i)
		if itm is NebulasNFT and itm.token_id == id:
			return itm
	return null

var loaded = null
func _update_contract():
	var f = File.new()
	var fname = "user://nrc721_" + network_as_name(network) + "_" + address + ".json"

	if loaded != fname and f.file_exists(fname):
		f.open(fname, File.READ)
		var res: JSONParseResult = JSON.parse(f.get_as_text())
		f.close()
		
		if res.error == OK:
			loaded = fname
			token_name = res.result.name
			if NebulasWalletSingleton != null and !Engine.is_editor_hint():
				NebulasWalletSingleton.register_nrc721(self)

	if NebulasWalletSingleton == null:
		return
	
	if loaded != fname and is_inside_tree() and !Engine.is_editor_hint():
		if NebulasWalletSingleton and NebulasWalletSingleton.initialized:
			if address != null and len(address) == 35 and address.begins_with("n"):
				_call_ro_contract_function("name", [])
				var name_result = yield(self, "http_finished_normalized")
				if name_result.has("result"):
					token_name = JSON.parse(name_result.result.result).result
				else:
					return
					
				NebulasWalletSingleton.register_nrc721(self)
				f.open(fname, File.WRITE)
				f.store_string(JSON.print({
					"name": token_name
				}))
				f.close()
				loaded = fname

func _call_ro_contract_function(contract_function, contract_args):
	var url = NebulasWalletSingleton.build_url_for_method('call')
	var source_address = address  # Doesn't needs to be our own address, it's read-only anyways and we don't care the execution result
	#if Engine.editor_hint:
	#	source_address = address  # Doesn't needs to be our own address, it's read-only anyways and we don't care the execution result
	#else:
	#	source_address = NebulasWalletSingleton.get_address()
		
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

func _mint_token():
	var deployer = get_parent()
	if deployer._current_warning != '':
		emit_signal("mint_result", {"error": "Contract deployer isn't unlocked"})
		return
	
	deployer.get_account_state()
	yield(deployer, "account_state")
	
	var tx = deployer.new_transaction()
	tx.to = address
	tx.value = 0

	var c = Crypto.new()
	var id = '0x' + c.generate_random_bytes(8).hex_encode()
	tx.contract_call = {
		"Function": "createToken",
		"Args": JSON.print([id])
	}
	
	tx.estimate_gas()
	var result = yield(tx, 'tx_result')
	
	if result:
		if tx.send_tx(1):
			var tx_result: Dictionary = yield(tx, 'tx_result')
			print(tx_result)
			if tx_result.has("result") and tx_result.result.has("result"):
				var txhash =  tx_result.result.result.txhash
				
				emit_signal("mint_result", {"id": id, "txhash": txhash})
			else:
				var err = JSON.parse(tx_result.error.body)
				emit_signal("mint_result", {"error": err.result.error})
		else:
			emit_signal("mint_result", {"error": "couldn't send transaction"})
	else:
		emit_signal("mint_result", {"error": "couldn't estimate gas"})

func create_transfer(tx, to: String, id: String):
	tx.to = address
	tx.value = 0
	tx.contract_call = {
		"Function": "transferFrom",
		"Args": JSON.print([tx.wallet.get_address(), to, id])
	}
	#tx.
	
func _do_transfer(to: String, id: String):
	var deployer = get_parent()
	if deployer._current_warning != '':
		emit_signal("mint_result", {"error": "Contract deployer isn't unlocked"})
		return
	
	deployer.get_account_state()
	yield(deployer, "account_state")
	
	var tx = deployer.new_transaction()
	tx.to = address
	tx.value = 0

	create_transfer(tx, to, id)
	
	tx.estimate_gas()
	var result = yield(tx, 'tx_result')
	
	if result:
		if tx.send_tx(1):
			var tx_result: Dictionary = yield(tx, 'tx_result')
			print(tx_result)
			if tx_result.has("result") and tx_result.result.has("result"):
				var txhash =  tx_result.result.result.txhash
				
				emit_signal("transfer_result", {"id": id, "txhash": txhash})
			else:
				var err = JSON.parse(tx_result.error.body)
				emit_signal("transfer_result", {"error": err.result.error})
		else:
			emit_signal("transfer_result", {"error": "couldn't send transaction"})
	else:
		emit_signal("transfer_result", {"error": "couldn't estimate gas"})

const standard_nrc721_contract = """
'use strict';

var Operator = function (obj) {
	this.operator = {};
	this.parse(obj);
};

Operator.prototype = {
	toString: function () {
		return JSON.stringify(this.operator);
	},

	parse: function (obj) {
		if (typeof obj != "undefined") {
			var data = JSON.parse(obj);
			for (var key in data) {
				this.operator[key] = data[key];
			}
		}
	},

	get: function (key) {
		return this.operator[key];
	},

	set: function (key, value) {
		this.operator[key] = value;
	}
};

var StandardToken = function () {
	LocalContractStorage.defineProperties(this, {
		_name: null,
		_deployer: null
	});

	LocalContractStorage.defineMapProperties(this, {
		"tokenOwner": null,
		"ownedTokensCount": {
			parse: function (value) {
				return new BigNumber(value);
			},
			stringify: function (o) {
				return o.toString(10);
			}
		},
		"tokenApprovals": null,
		"operatorApprovals": {
			parse: function (value) {
				return new Operator(value);
			},
			stringify: function (o) {
				return o.toString();
			}
		},
		
	});
};

StandardToken.prototype = {
	init: function (name) {
		this._name = name;
		this._deployer = Blockchain.transaction.from;
	},

	name: function () {
		return this._name;
	},

	// Returns the number of tokens owned by owner.
	balanceOf: function (owner) {
		var balance = this.ownedTokensCount.get(owner);
		if (balance instanceof BigNumber) {
			return balance.toString(10);
		} else {
			return "0";
		}
	},

	//Returns the address of the owner of the tokenID.
	ownerOf: function (tokenID) {
		return this.tokenOwner.get(tokenID);
	},

	/**
	 * Set or reaffirm the approved address for an token.
	 * The function SHOULD throws unless transcation from is the current token owner, or an authorized operator of the current owner.
	 */
	approve: function (to, tokenId) {
		var from = Blockchain.transaction.from;

		var owner = this.ownerOf(tokenId);
		if (to == owner) {
			throw new Error("invalid address in approve.");
		}
		if (owner == from || this.isApprovedForAll(owner, from)) {
			this.tokenApprovals.set(tokenId, to);
			this._approveEvent(true, owner, to, tokenId);
		} else {
			throw new Error("permission denied in approve.");
		}
	},

	// Returns the approved address for a single token.
	getApproved: function (tokenId) {
		return this.tokenApprovals.get(tokenId);
	},

	/**
	 * Enable or disable approval for a third party (operator) to manage all of transaction from's assets.
	 * operator Address to add to the set of authorized operators. 
	 * @param approved True if the operators is approved, false to revoke approval
	 */
	setApprovalForAll: function(to, approved) {
		var from = Blockchain.transaction.from;
		if (from == to) {
			throw new Error("invalid address in setApprovalForAll.");
		}
		var operator = this.operatorApprovals.get(from) || new Operator();
		operator.set(to, approved);
		this.operatorApprovals.set(from, operator);
	},

	/**
	 * @dev Tells whether an operator is approved by a given owner
	 * @param owner owner address which you want to query the approval of
	 * @param operator operator address which you want to query the approval of
	 * @return bool whether the given operator is approved by the given owner
	 */
	isApprovedForAll: function(owner, operator) {
		var operator = this.operatorApprovals.get(owner);
		if (operator != null) {
			if (operator.get(operator) === "true") {
				return true;
			} else {
				return false;
			}
		}
	},


	/**
	 * @dev Returns whether the given spender can transfer a given token ID
	 * @param spender address of the spender to query
	 * @param tokenId uint256 ID of the token to be transferred
	 * @return bool whether the msg.sender is approved for the given token ID,
	 *  is an operator of the owner, or is the owner of the token
	 */
	_isApprovedOrOwner: function(spender, tokenId) {
		var owner = this.ownerOf(tokenId);
		return spender == owner || this.getApproved(tokenId) == spender || this.isApprovedForAll(owner, spender);
	},

	/**
	 * Transfers the ownership of an token from one address to another address. 
	 * The caller is responsible to confirm that to is capable of receiving token or else they may be permanently lost.
	 * Transfers tokenId from address from to address to, and MUST fire the Transfer event.
	 * The function SHOULD throws unless the transaction from is the current owner, an authorized operator, or the approved address for this token. 
	 * Throws if from is not the current owner. 
	 * Throws if to is the contract address. 
	 * Throws if tokenId is not a valid token.
	 */
	transferFrom: function (from, to, tokenId) {
		var sender = Blockchain.transaction.from;
		var contractAddress = Blockchain.transaction.to;
		if (contractAddress == to) {
			throw new Error("Forbidden to transfer money to a smart contract address");
		}
		if (this._isApprovedOrOwner(sender, tokenId)) {
			this._clearApproval(from, tokenId);
			this._removeTokenFrom(from, tokenId);
			this._addTokenTo(to, tokenId);
			this._transferEvent(true, from, to, tokenId);
		} else {
			throw new Error("permission denied in transferFrom.");
		}
		
	},


	 /**
	 * Internal function to clear current approval of a given token ID
	 * Throws if the given address is not indeed the owner of the token
	 * @param sender owner of the token
	 * @param tokenId uint256 ID of the token to be transferred
	 */
	_clearApproval: function (sender, tokenId) {
		var owner = this.ownerOf(tokenId);
		if (sender != owner) {
			throw new Error("permission denied in clearApproval.");
		}
		this.tokenApprovals.del(tokenId);
	},

	/**
	 * Internal function to remove a token ID from the list of a given address
	 * @param from address representing the previous owner of the given token ID
	 * @param tokenId uint256 ID of the token to be removed from the tokens list of the given address
	 */
	_removeTokenFrom: function(from, tokenId) {
		if (from != this.ownerOf(tokenId)) {
			throw new Error("permission denied in removeTokenFrom.");
		}
		var tokenCount = this.ownedTokensCount.get(from);
		if (tokenCount.lt(1)) {
			throw new Error("Insufficient account balance in removeTokenFrom.");
		}
		this.ownedTokensCount.set(from, tokenCount.sub(1));
	},

	/**
	 * Internal function to add a token ID to the list of a given address
	 * @param to address representing the new owner of the given token ID
	 * @param tokenId uint256 ID of the token to be added to the tokens list of the given address
	 */
	_addTokenTo: function(to, tokenId) {
		this.tokenOwner.set(tokenId, to);
		var tokenCount = this.ownedTokensCount.get(to) || new BigNumber(0);
		this.ownedTokensCount.set(to, tokenCount.add(1));
	},

	/**
	 * Internal function to mint a new token
	 * @param to The address that will own the minted token
	 * @param tokenId uint256 ID of the token to be minted by the msg.sender
	 */
	_mint: function(to, tokenId) {
		this._addTokenTo(to, tokenId);
		this._transferEvent(true, "", to, tokenId);
	},
	
	createToken: function(tokenId) {
		var from = Blockchain.transaction.from;
		if (from === this._deployer) {
			this._mint(from, tokenId);
		} else {
			throw new Error("Must be transaction deployer to use the createToken function.");
		}
	},

	/**
	 * Internal function to burn a specific token
	 * @param tokenId uint256 ID of the token being burned by the msg.sender
	 */
	_burn: function(owner, tokenId) {
		this._clearApproval(owner, tokenId);
		this._removeTokenFrom(owner, tokenId);
		this._transferEvent(true, owner, "", tokenId);
	},

	_transferEvent: function (status, from, to, tokenId) {
		Event.Trigger(this.name(), {
			Status: status,
			Transfer: {
				from: from,
				to: to,
				tokenId: tokenId
			}
		});
	},

	_approveEvent: function (status, owner, spender, tokenId) {
		Event.Trigger(this.name(), {
			Status: status,
			Approve: {
				owner: owner,
				spender: spender,
				tokenId: tokenId
			}
		});
	}

};

module.exports = StandardToken;
"""
