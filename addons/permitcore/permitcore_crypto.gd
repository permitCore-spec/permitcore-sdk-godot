extends RefCounted
## Uses Godot's mbedTLS-backed Crypto API. No custom elliptic-curve arithmetic.
const Types = preload("permitcore_types.gd")
const P256_SPKI_PREFIX := "3059301306072a8648ce3d020106082a8648ce3d03010703420004"

static func verify_token(token: String, public_key_base64: String, prefix: String, deadline: String) -> Types.TokenResult:
	var result := Types.TokenResult.new()
	result.message = "Invalid or corrupt token."
	var parts := token.split(".")
	if parts.size() != 3 or parts[0] != prefix:
		return result
	var key_bytes := _decode(public_key_base64, false)
	if key_bytes.size() != 91 or key_bytes.slice(0, 27).hex_encode() != P256_SPKI_PREFIX:
		return result
	var signature := _decode(parts[2], true)
	if signature.size() != 64:
		return result
	var key := CryptoKey.new()
	var pem := "-----BEGIN PUBLIC KEY-----\n" + Marshalls.raw_to_base64(key_bytes) + "\n-----END PUBLIC KEY-----\n"
	if key.load_from_string(pem, true) != OK:
		return result
	var integers := _integer(signature.slice(0, 32)) + _integer(signature.slice(32, 64))
	var der := PackedByteArray([48, integers.size()]) + integers
	if not Crypto.new().verify(HashingContext.HASH_SHA256, parts[1].sha256_buffer(), der, key):
		return result
	var bytes := _decode(parts[1], true)
	var json := JSON.new()
	if bytes.is_empty() or json.parse(bytes.get_string_from_utf8()) != OK or not json.data is Dictionary:
		return result
	var value: Dictionary = json.data
	if value.get("version") != 1 or not value.get(deadline) is String:
		return result
	result.payload = value.duplicate(true)
	if _utc_timestamp(value[deadline]) <= Time.get_unix_time_from_system():
		result.message = "Token expired."
		return result
	result.is_valid = true
	result.message = "Valid."
	return result

static func _decode(value: String, url: bool) -> PackedByteArray:
	var pattern := "^[A-Za-z0-9_-]+$" if url else "^[A-Za-z0-9+/]+={0,2}$"
	var regex := RegEx.new()
	regex.compile(pattern)
	if regex.search(value) == null or value.length() % 4 == 1:
		return PackedByteArray()
	var normalized := value.replace("-", "+").replace("_", "/")
	while normalized.length() % 4 != 0:
		normalized += "="
	return Marshalls.base64_to_raw(normalized)

static func _integer(value: PackedByteArray) -> PackedByteArray:
	while value.size() > 1 and value[0] == 0:
		value = value.slice(1)
	if value[0] >= 128:
		value = PackedByteArray([0]) + value
	return PackedByteArray([2, value.size()]) + value

static func _utc_timestamp(value: String) -> float:
	var regex := RegEx.new()
	regex.compile("^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(?:\\.(\\d{1,7}))?(Z|[+-]\\d{2}:\\d{2})$")
	var match := regex.search(value)
	if match == null:
		return 0.0
	var offset := 0
	var zone := match.get_string(3)
	if zone != "Z":
		var hours := zone.substr(1, 2).to_int()
		var minutes := zone.substr(4, 2).to_int()
		if hours > 23 or minutes > 59:
			return 0.0
		offset = (hours * 3600 + minutes * 60) * (1 if zone[0] == "+" else -1)
	var fraction := 0.0 if match.get_string(2).is_empty() else ("0." + match.get_string(2)).to_float()
	return float(Time.get_unix_time_from_datetime_string(match.get_string(1))) + fraction - offset
