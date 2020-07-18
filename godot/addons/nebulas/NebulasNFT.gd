extends Node
tool
class_name NebulasNFT

signal balance_updated

export(String) var token_id
export(String) var asset_title
export(String, MULTILINE) var asset_description
export(PackedScene) var ingame_asset
export(PackedScene) var wallet_asset
export(bool) var mint_token setget _set_mint, _get_readonly
export(String) var transfer_to_address
export(bool) var do_transfer_to_address setget _set_do_transfer, _get_readonly
export(String) var transfer_txhash setget _set_readonly

var _current_warning = ''
var _is_minting = false
var _is_transferring = false
var _allow_readonly_write = false

var balance = 0

func _get_configuration_warning():
	return _current_warning

func _check_preconditions():
	var prnt = get_parent()
	_current_warning = ''
	if !prnt.has_method('_mint_token'):
		_current_warning = 'NebulasNFT must be parented to a NebulasContractNRC721'
	elif len(prnt.address) == 0:
		_current_warning = 'Parent NebulasContractNRC721 should be deployed'
	elif len(token_id) == 0:
		_current_warning = 'Token won\'t be usable till you mint it'
	update_configuration_warning()

func _ready():
	_check_preconditions()
	if !Engine.editor_hint:
		NebulasWalletSingleton.register_nft(self)

func _set_mint(v):
	if _is_minting:
		_current_warning = 'Your token is being minted, wait till completion'
		update_configuration_warning()
		return

	if v and len(token_id) == 0:
		var prnt = get_parent()
		_is_minting = true
		prnt._mint_token()
		prnt.connect("mint_result", self, "_mint_result", [], CONNECT_ONESHOT)

func _mint_result(result):
	_is_minting = false
	_current_warning = ''

	if result.has('error'):
		_current_warning = 'Token couldn\'t be minted: ' + result.error
	else:
		_allow_readonly_write = true
		token_id = result.id
		_current_warning = ''
	update_configuration_warning()

func _set_do_transfer(v):
	if _is_transferring:
		_current_warning = 'Your token is being transferred, wait till completion'
		update_configuration_warning()
		return

	if v:
		if len(token_id) != 0:
			var prnt = get_parent()
			_is_transferring = true
			prnt._do_transfer(transfer_to_address, token_id)
			prnt.connect("transfer_result", self, "_transfer_result", [], CONNECT_ONESHOT)
		else:
			_current_warning = 'Token not minted, mint it first before transferring'
			update_configuration_warning()

func _transfer_result(result):
	_is_transferring = false
	_current_warning = ''

	if result.has('error'):
		_current_warning = 'Token couldn\'t be transferred: ' + result.error
	else:
		_current_warning = ''
		transfer_txhash = result.txhash
	update_configuration_warning()

func _set_readonly(v):
	pass # read only

func _get_readonly():
	return false

func _update_balance():
	var prnt = get_parent()
	if prnt.has_method('_call_ro_contract_function'):
		var own_address = NebulasWalletSingleton.get_address()
		prnt._call_ro_contract_function('ownerOf', [token_id])
		var result = yield(prnt, "http_finished_normalized")
		result = JSON.parse(result.result.result)
		if result.error == OK and result.result == own_address:
			balance = 1
		else:
			balance = 0
	else:
		print('NebulasNFT should be direct child of a NebulasContractNRC721 node')
	emit_signal("balance_updated")

func create_transfer(t, address):
	get_parent().create_transfer(t, address, token_id)
