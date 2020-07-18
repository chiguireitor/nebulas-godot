extends Node
tool
class_name NebulasTransaction

signal tx_result(res)

export(String) var from
export(String) var to
export(int) var value
export(int) var nonce
export(int) var gas_price
export(int) var gas_limit
export(String) var contract = ''
export(String) var contract_call = ''
export(PoolByteArray) var binary = null

var wallet
var current_gas = 0

var GAS_PRICE_MAX = 1000000000000
var GAS_LIMIT_MAX = 50000000000

var _current_tx_data = null
var estimation_error = ''

func _ready():
	pass

func estimate_gas():
	if wallet == null:
		return false

	var binary_encode = ''
	estimation_error = ''
	if binary != null:
		binary_encode = binary.hex_encode()

	var ob = {
		"from": from,
		"to": to,
		"value": str(value),
		"nonce": str(int(nonce) + 1),
		"gasPrice": str(gas_price),
		"gasLimit": str(gas_limit)
	}
	var delete_contract_from_ob = false

	if contract != null and len(contract) > 0:
		ob.contract = contract

	if contract_call != null and len(contract_call) > 0:
		var estimation_ob = {}
		for x in contract_call:
			estimation_ob[x.to_lower()] = contract_call[x]
		ob.contract = estimation_ob
		delete_contract_from_ob = true
	var response = yield(wallet.estimate_gas(ob), "estimate_gas")

	if response.has("error") and (!response.has("gas") or len(response.gas) == 0):
		emit_signal("tx_result", response)
	else:
		if delete_contract_from_ob:
			ob.contract = null
		var data = response.result.result
		if !(data.has("gas") and len(data.gas) > 0) and data.err != null and len(data.err) > 0:
			estimation_error = data.err
			emit_signal("tx_result", false)
		else:
			current_gas = data.gas
			ob.gasLimit = current_gas
			_current_tx_data = ob
			emit_signal("tx_result", true)

func send_tx(gas_mult=1):
	if _current_tx_data == null:
		return false

	var ob = _current_tx_data
	var gas_limit = min(int(ob.gasLimit) * gas_mult, GAS_LIMIT_MAX)
	wallet.neb.gas_price = str(min(int(ob.gasPrice) * gas_mult, GAS_PRICE_MAX))
	wallet.neb.gas_limit = str(gas_limit)
	var real_send_value = int(ob.value)

	var pba: PoolByteArray
	if contract_call != null:
		pba = wallet.neb.send_with_payload(ob.to, str(real_send_value), int(nonce) + 1, JSON.print(contract_call), "call")
	elif contract != null:
		pba = wallet.neb.send_with_payload(ob.to, str(real_send_value), int(nonce) + 1, JSON.print(contract), "deploy")
	elif binary != null:
		pba = wallet.neb.send_with_payload(ob.to, str(real_send_value), int(nonce) + 1, binary.hex_encode(), "binary")
	else:
		pba = wallet.neb.send(ob.to, str(real_send_value), int(nonce) + 1)
	wallet.connect("broadcast_tx", self, "tx_broadcast_result", [], CONNECT_ONESHOT)
	wallet.rawtransaction(pba)

	return true

func tx_broadcast_result(response):
	emit_signal("tx_result", response)
