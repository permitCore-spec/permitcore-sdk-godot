class_name PermitCoreClient
extends RefCounted
## Official Godot client. Call network operations with await from the SceneTree thread.
const VERSION := "2.2.0"
const Types = preload("permitcore_types.gd")
const TokenCrypto = preload("permitcore_crypto.gd")
const Transport = preload("permitcore_transport.gd")
var configuration_error: String = ""
var _base_url: String
var _enable_cache: bool
var _cache_directory: String
var _trusted_public_keys: Array[String] = []
var _device_id: String
var _timeout: float
var _max_retries: int
var _hardware_id: String = ""
var _tls_ca: X509Certificate

func _init(base_url: String = "", options: Dictionary = {}) -> void:
	_base_url = base_url.trim_suffix("/")
	_enable_cache = options.get("enable_offline_cache", true) == true
	_cache_directory = str(options.get("cache_directory", "user://permitcore"))
	_device_id = str(options.get("device_id", "")).strip_edges().to_lower()
	var timeout_value: Variant = options.get("timeout_seconds", 10.0)
	var retry_value: Variant = options.get("max_retries", 2)
	_timeout = float(timeout_value) if timeout_value is float or timeout_value is int else 0.0
	_max_retries = retry_value if retry_value is int else -1
	var ca_file: Variant = options.get("tls_ca_file", "")
	if not ca_file is String:
		configuration_error = "tls_ca_file must be a path to an independently trusted PEM CA certificate."
	elif not ca_file.is_empty():
		_tls_ca = X509Certificate.new()
		if _tls_ca.load(ca_file) != OK:
			configuration_error = "Cannot load configured TLS CA certificate."
	var url := RegEx.new()
	url.compile("^https?://[^/?#@\\s]+(?:/[^?#\\s]*)?$")
	if url.search(_base_url) == null or not is_finite(_timeout) or _timeout <= 0.0 or _max_retries < 0 or _max_retries > 5:
		configuration_error = "A valid HTTP(S) API URL, positive timeout and max_retries from 0 to 5 are required."
	var pins: Variant = options.get("trusted_public_keys", [])
	if not pins is Array:
		configuration_error = "trusted_public_keys must be an array of SPKI base64 strings."
	else:
		for pin in pins:
			if not pin is String:
				configuration_error = "trusted_public_keys must contain only strings."
			else:
				_trusted_public_keys.append(pin)

func validate(license_key: String, version: String = "", expected_product_id: String = "") -> Types.LicenseResult:
	var device := _effective_device_id()
	var body := {"licenseKey": license_key}
	if _enable_cache and not _trusted_public_keys.is_empty():
		body.deviceId = device
	_optional(body, "version", version)
	_optional(body, "expectedProductId", expected_product_id)
	var response := await _request("api/v1/validate", HTTPClient.METHOD_POST, body)
	return _license_response(response, license_key, device, expected_product_id, false)

func activate(license_key: String, device_id: String = "", device_name: String = "", version: String = "", expected_product_id: String = "") -> Types.LicenseResult:
	var device := _effective_device_id(device_id)
	var nonce := await _request("api/v1/nonce", HTTPClient.METHOD_GET)
	if nonce.kind != "ok":
		return _license_response(nonce, license_key, device, expected_product_id, true)
	if not nonce.data is Dictionary or not nonce.data.get("nonce") is String or str(nonce.data.nonce).strip_edges().is_empty():
		return _license_failure("InvalidResponse", "Invalid nonce response.")
	var body := {"licenseKey": license_key, "deviceId": device, "nonce": nonce.data.nonce}
	_optional(body, "deviceName", device_name)
	_optional(body, "version", version)
	_optional(body, "expectedProductId", expected_product_id)
	var response := await _request("api/v1/activate", HTTPClient.METHOD_POST, body)
	return _license_response(response, license_key, device, expected_product_id, true)

func deactivate(tenant_slug: String, license_key: String, activation_id: String) -> bool:
	# Existing proof cannot be erased remotely. Clearing this key's local cache is best effort.
	var path := _cache_path(license_key)
	if FileAccess.file_exists(path):
		DirAccess.remove_absolute(ProjectSettings.globalize_path(path))
	var response := await _request("api/v1/portal/" + tenant_slug.uri_encode() + "/deactivate", HTTPClient.METHOD_POST, {"licenseKey": license_key, "activationId": activation_id})
	return response.status == 204 and response.kind == "ok"

func meter(license_key: String, event_name: String, quantity: int = 1, meta: Variant = null) -> bool:
	var body := {"licenseKey": license_key, "eventName": event_name, "quantity": maxi(1, quantity)}
	if meta != null:
		body.meta = meta
	var response := await _request("api/v1/meter", HTTPClient.METHOD_POST, body)
	return response.kind == "ok" and response.data is Dictionary and response.data.get("recorded") is bool and response.data.recorded == true

func checkout(license_key: String, device_id: String = "", device_name: String = "") -> Types.FloatingSession:
	var body := {"licenseKey": license_key, "deviceId": _effective_device_id(device_id)}
	_optional(body, "deviceName", device_name)
	return await _floating("checkout", body)

func heartbeat(session_token: String) -> Types.FloatingSession:
	return await _floating("heartbeat", {"sessionToken": session_token})

func try_checkin(session_token: String) -> bool:
	var response := await _request("api/v1/float/checkin", HTTPClient.METHOD_POST, {"sessionToken": session_token})
	return response.kind == "ok" and response.status == 204

func checkin(session_token: String) -> void:
	await try_checkin(session_token)

func get_hardware_id() -> String:
	if not _hardware_id.is_empty():
		return _hardware_id
	var path := _cache_directory.path_join(".permitcore_seed")
	var seed := FileAccess.get_file_as_string(path).strip_edges() if FileAccess.file_exists(path) else ""
	if seed.is_empty():
		seed = Crypto.new().generate_random_bytes(32).hex_encode()
		_write_text(path, seed)
	# Private application-scoped identifier, not attestation or proof against VM cloning.
	_hardware_id = (OS.get_name() + "|" + OS.get_unique_id() + "|" + seed).sha256_text()
	return _hardware_id

static func verify_offline_token(token: String, public_key_base64: String) -> Types.TokenResult:
	return TokenCrypto.verify_token(token, public_key_base64, "pc_offline_v1", "expiresAt")

static func verify_grace_cache_token(token: String, public_key_base64: String) -> Types.TokenResult:
	return TokenCrypto.verify_token(token, public_key_base64, "pc_grace_v1", "validUntil")

func activate_offline(token: String, device_id: String = "", expected_product_id: String = "") -> Types.TokenResult:
	var device := _effective_device_id(device_id)
	var result := _trusted_offline(token, device, expected_product_id)
	if result.is_valid and _enable_cache:
		_write_text(_offline_path(device), JSON.stringify({"token": token}))
	return result

func validate_offline(device_id: String = "", expected_product_id: String = "") -> Types.TokenResult:
	if not _enable_cache:
		return _token_failure("Offline caching is disabled.")
	var device := _effective_device_id(device_id)
	var token := _read_token(_offline_path(device))
	return _trusted_offline(token, device, expected_product_id)

func verify_offline_online(token: String) -> Types.TokenResult:
	var response := await _request("api/v1/offline/verify", HTTPClient.METHOD_POST, {"token": token})
	if response.kind != "ok" or not response.data is Dictionary or not response.data.get("isValid") is bool:
		return _token_failure("Cannot verify offline token with server.")
	var result := Types.TokenResult.new()
	result.is_valid = response.data.isValid
	result.is_revoked = response.data.get("isRevoked") == true
	result.message = str(response.data.get("message", ""))
	result.data = response.data.duplicate(true)
	if response.data.get("payload") is Dictionary:
		result.payload = response.data.payload.duplicate(true)
	return result

func _license_response(response: Dictionary, key: String, device: String, product: String, activation: bool) -> Types.LicenseResult:
	if response.kind == "configuration":
		return _license_failure("InvalidConfiguration", configuration_error)
	if response.kind == "http":
		var data: Dictionary = response.data if response.data is Dictionary else {}
		var code: Variant = data.get("errorCode")
		var message: Variant = data.get("message")
		var rejected := Types.LicenseResult.from_wire(data)
		rejected.is_valid = false
		rejected.is_offline = false
		rejected.offline_cache_token = ""
		rejected.error_code = code if code is String and not code.is_empty() else "HttpError"
		rejected.message = message if message is String and not message.is_empty() else "HTTP %d." % response.status
		rejected.data.merge({"isValid":false, "isOffline":false, "offlineCacheToken":null}, true)
		return rejected
	if response.kind == "invalid":
		return _license_failure("InvalidResponse", "Invalid response from server.")
	if response.kind == "transient":
		var cached := _load_cache(key, device, product, activation)
		if cached != null:
			return cached
		return _license_failure("RequestFailed", "Cannot reach license server.", true)
	if not response.data is Dictionary or not response.data.get("isValid") is bool:
		return _license_failure("InvalidResponse", "Invalid response from server.")
	var data: Dictionary = response.data
	if data.get("errorCode") != null and not data.errorCode is String:
		return _license_failure("InvalidResponse", "Invalid response from server.")
	var result := Types.LicenseResult.from_wire(data)
	result.is_offline = false
	if not result.is_valid:
		result.offline_cache_token = ""
		result.data["offlineCacheToken"] = null
	elif _enable_cache and not result.offline_cache_token.is_empty():
		if not _trusted_grace(result.offline_cache_token, key, device, product, activation).is_empty():
			_write_text(_cache_path(key), JSON.stringify({"token": result.offline_cache_token}))
	return result

func _floating(operation: String, body: Dictionary) -> Types.FloatingSession:
	var result := Types.FloatingSession.new()
	result.error_code = "RequestFailed"
	result.message = "Cannot complete floating request."
	var response := await _request("api/v1/float/" + operation, HTTPClient.METHOD_POST, body)
	if response.kind != "ok" or not response.data is Dictionary or not response.data.get("success") is bool:
		return result
	var data: Dictionary = response.data
	for field in ["sessionToken", "expiresAt", "message", "errorCode"]:
		if data.get(field) != null and not data[field] is String:
			return result
	if not data.success:
		result.error_code = _text(data.get("errorCode"), "FloatingDenied")
		result.message = _text(data.get("message"), "Floating request denied.")
		return result
	if _text(data.get("sessionToken")).strip_edges().is_empty() or _text(data.get("expiresAt")).strip_edges().is_empty():
		return result
	result.success = true
	result.session_token = data.sessionToken
	result.expires_at = data.expiresAt
	result.message = _text(data.get("message"))
	result.error_code = ""
	return result

func _trusted_offline(token: String, device: String, product: String) -> Types.TokenResult:
	for pin in _trusted_public_keys:
		var result := verify_offline_token(token, pin)
		var p := result.payload
		if result.is_valid and p.get("deviceId") is String and p.deviceId.strip_edges().to_lower() == device and (product.is_empty() or p.get("productId") is String and p.productId.to_lower() == product.to_lower()):
			return result
	return _token_failure("Offline token trust or context check failed.")

func _trusted_grace(token: String, key: String, device: String, product: String, activation: bool) -> Dictionary:
	for pin in _trusted_public_keys:
		var result := verify_grace_cache_token(token, pin)
		var p := result.payload
		if not result.is_valid or not p.get("isValid") is bool or p.isValid != true or p.get("licenseKeySha256") != key.sha256_text():
			continue
		if not p.get("productId") is String or str(p.productId).is_empty() or not product.is_empty() and p.productId.to_lower() != product.to_lower():
			continue
		if p.get("deviceId") != null and (not p.deviceId is String or p.deviceId.strip_edges().to_lower() != device):
			continue
		if (activation or not p.get("nodeLocked") is bool or p.nodeLocked != false) and (not p.get("deviceActivated") is bool or p.deviceActivated != true or not p.get("deviceId") is String or str(p.deviceId).is_empty()):
			continue
		return p
	return {}

func _load_cache(key: String, device: String, product: String, activation: bool) -> Types.LicenseResult:
	if not _enable_cache:
		return null
	var p := _trusted_grace(_read_token(_cache_path(key)), key, device, product, activation)
	if p.is_empty():
		return null
	var result := Types.LicenseResult.from_wire(p)
	result.is_offline = true
	result.message = "Offline mode — cryptographically verified until " + str(p.get("validUntil", ""))
	return result

func _request(path: String, method: HTTPClient.Method, payload: Variant = null) -> Dictionary:
	if not configuration_error.is_empty():
		return {"kind":"configuration", "status":0, "data":null}
	var tree := Engine.get_main_loop() as SceneTree
	if tree == null:
		return {"kind":"transient", "status":0, "data":null}
	var safe := method == HTTPClient.METHOD_GET and (path == "api/v1/nonce" or path.ends_with("/public-key")) or method == HTTPClient.METHOD_POST and path in ["api/v1/validate", "api/v1/float/heartbeat"]
	for attempt in range(_max_retries + 1):
		var response := await _attempt(tree, path, method, payload)
		if response.kind != "transient" or not safe or attempt == _max_retries:
			return response
		await tree.create_timer(minf(0.25 * pow(2.0, attempt), 2.0), true, false, true).timeout
	return {"kind":"transient", "status":0, "data":null}

func _attempt(tree: SceneTree, path: String, method: HTTPClient.Method, payload: Variant) -> Dictionary:
	return await Transport.request(tree, _base_url + "/" + path, method, payload, _timeout, _tls_ca)

func _effective_device_id(override: String = "") -> String:
	var value := override.strip_edges()
	if value.is_empty():
		value = _device_id if not _device_id.is_empty() else get_hardware_id()
	return value.to_lower()

func _cache_path(key: String) -> String:
	return _cache_directory.path_join(".permitcore_cache_v2_" + key.sha256_text())

func _offline_path(device: String) -> String:
	return _cache_directory.path_join(".permitcore_offline_v2_" + device.sha256_text())

static func _read_token(path: String) -> String:
	if not FileAccess.file_exists(path):
		return ""
	var file := FileAccess.open(path, FileAccess.READ)
	if file == null or file.get_length() > 4 * 1024 * 1024:
		return ""
	var json := JSON.new()
	if json.parse(file.get_as_text()) != OK or not json.data is Dictionary or not json.data.get("token") is String:
		return ""
	return json.data.token

static func _write_text(path: String, text: String) -> void:
	var absolute := ProjectSettings.globalize_path(path)
	if DirAccess.make_dir_recursive_absolute(absolute.get_base_dir()) != OK:
		return
	var file := FileAccess.open(path, FileAccess.WRITE)
	if file != null:
		file.store_string(text)

static func _optional(body: Dictionary, field: String, value: String) -> void:
	if not value.is_empty():
		body[field] = value

static func _text(value: Variant, fallback: String = "") -> String:
	return value if value is String and not value.is_empty() else fallback

static func _license_failure(code: String, message: String, offline: bool = false) -> Types.LicenseResult:
	var result := Types.LicenseResult.new()
	result.error_code = code
	result.message = message
	result.is_offline = offline
	return result

static func _token_failure(message: String) -> Types.TokenResult:
	var result := Types.TokenResult.new()
	result.message = message
	return result
