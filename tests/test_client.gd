extends SceneTree
const Client = preload("../addons/permitcore/permitcore_client.gd")
const Types = preload("../addons/permitcore/permitcore_types.gd")
var _checks: int = 0
var _failures: Array[String] = []
var _base: String = ""
var _vectors: Dictionary
var _contract: Dictionary
var _cache_root: String
const KEY := "PERMIT-TEST-VECT-0R00-0001"
const PRODUCT := "44444444-4444-4444-4444-444444444444"
const DEVICE := "test-device-001"

func _initialize() -> void:
	call_deferred("_run")

func _check(value: bool, name: String) -> void:
	_checks += 1
	if not value:
		_failures.append(name)
		printerr("FAIL: " + name)

func _load(name: String) -> Dictionary:
	var path := "res://test-vectors/" + name
	if not FileAccess.file_exists(path):
		path = ProjectSettings.globalize_path("res://").path_join("../test-vectors/" + name)
	return JSON.parse_string(FileAccess.get_file_as_string(path))

func _client(case_name: String = "", options: Dictionary = {}) -> Client:
	var defaults := {"cache_directory":_cache_root.path_join(case_name), "device_id":DEVICE, "trusted_public_keys":[_vectors.signingKeyPair.publicKeyBase64Spki], "timeout_seconds":0.4, "max_retries":0}
	defaults.merge(options, true)
	return Client.new(_base + "/" + case_name, defaults)

func _run() -> void:
	_vectors = _load("vectors.json")
	_contract = _load("http-contract.json")
	var args := OS.get_cmdline_user_args()
	if not args.is_empty():
		_base = args[0]
	_cache_root = args[1] if args.size() > 1 else "user://native-tests-" + Crypto.new().generate_random_bytes(8).hex_encode()
	for group in ["offlineTokenVectors", "graceTokenVectors"]:
		for vector in _vectors[group]:
			var result: Types.TokenResult
			if group == "offlineTokenVectors":
				result = Client.verify_offline_token(vector.token, _vectors.signingKeyPair.publicKeyBase64Spki)
			else:
				result = Client.verify_grace_cache_token(vector.token, _vectors.signingKeyPair.publicKeyBase64Spki)
			_check(result.is_valid == vector.expectValid, group + "/" + vector.name)
			if vector.has("expectedPayload") and result.is_valid:
				for field in vector.expectedPayload:
					_check(result.payload.get(field) == vector.expectedPayload[field], vector.name + "/" + field)
	for vector in _contract.featureCases:
		var result := Types.LicenseResult.from_wire({"isValid":true, "features":vector.features})
		_check(result.has_feature(vector.feature) == vector.expected, "feature/" + vector.name)
	_check(not Client.verify_offline_token(_vectors.offlineTokenVectors[0].token, _vectors.wrongKeyPairPublicKeyForReference.publicKeyBase64Spki).is_valid, "wrong SPKI")
	_check(not Client.verify_offline_token(_vectors.offlineTokenVectors[0].token, "invalid").is_valid, "malformed SPKI")
	var local := _client("manual")
	var token: String = _vectors.offlineTokenVectors[0].token
	_check(local.activate_offline(token, " TEST-DEVICE-001 ", PRODUCT).is_valid, "manual activation")
	_check(local.validate_offline(DEVICE, PRODUCT).is_valid, "manual read")
	_check(not local.validate_offline("other", PRODUCT).is_valid, "manual wrong device")
	_check(not local.validate_offline(DEVICE, "other").is_valid, "manual wrong product")
	var unpinned := _client("manual", {"trusted_public_keys":[]})
	_check(not unpinned.activate_offline(token, DEVICE, PRODUCT).is_valid, "manual no configured trust")
	var disabled := _client("manual", {"enable_offline_cache":false})
	_check(not disabled.validate_offline(DEVICE, PRODUCT).is_valid, "manual disabled cache")
	_check(local.get_hardware_id() == local.get_hardware_id(), "stable device seed")
	_check(local.get_hardware_id().length() == 64, "private hashed device")
	for invalid in [{"timeout_seconds":0}, {"timeout_seconds":-1}, {"max_retries":6}, {"max_retries":-1}, {"max_retries":1.2}, {"trusted_public_keys":[42]}]:
		_check(not _client("invalid", invalid).configuration_error.is_empty(), "invalid options " + str(invalid))
	if not _base.is_empty():
		await _http_cases()
		if args.size() > 2:
			await _security_cases(JSON.parse_string(FileAccess.get_file_as_string(args[2])))
	var report := {"result":"PASS" if _failures.is_empty() else "FAIL", "checks":_checks, "failures":_failures, "engine":Engine.get_version_info().string, "httpFixtures":not _base.is_empty()}
	print(JSON.stringify(report))
	quit(0 if _failures.is_empty() else 1)

func _http_cases() -> void:
	for group in ["httpAuthority", "httpLicenseResponses", "httpTransientResponses"]:
		for index in range(_contract[group].size()):
			var vector: Dictionary = _contract[group][index]
			var id: String = group + "-" + str(index)
			var result := await _client(id).validate(KEY, "1.0", PRODUCT)
			_check(result.is_valid == vector.get("expectedValid", false), id + "/valid")
			_check(result.error_code == vector.errorCode, id + "/errorCode")
			_check(result.is_offline == vector.get("expectedOffline", false), id + "/offline")
	for index in range(_contract.floatingCases.size()):
		var vector: Dictionary = _contract.floatingCases[index]
		var id := "floatingCases-" + str(index)
		var client := _client(id)
		if vector.operation == "checkin":
			_check(await client.try_checkin("test-session") == vector.expectedReleased, id)
		else:
			var result := await client.checkout(KEY, DEVICE, "Fictional desktop") if vector.operation == "checkout" else await client.heartbeat("test-session")
			_check(result.success == vector.expectedSuccess, id + "/success")
			_check(result.error_code == vector.get("expectedErrorCode", ""), id + "/errorCode")
			if not result.success:
				_check(result.session_token.is_empty() and result.expires_at.is_empty(), id + "/no credentials")
	for index in range(_contract.operationCases.size()):
		var vector: Dictionary = _contract.operationCases[index]
		var id := "operationCases-" + str(index)
		var client := _client(id)
		var result: bool
		if vector.operation == "deactivate":
			result = await client.deactivate("qa-tenant", "QA-DEVICE-KEY", "11111111-2222-3333-4444-555555555555")
		else:
			result = await client.meter("QA-METER-KEY", "qa_export", vector.get("quantity", 3), vector.get("meta", {"source":"qa", "nested":{"ok":true, "labels":["one","two"], "value":null}}))
		_check(result == vector.get("expectedReleased", false), id)
	for index in range(_contract.transportCases.size()):
		var vector: Dictionary = _contract.transportCases[index]
		var id := "transportCases-" + str(index)
		var client := _client(id, {"max_retries":int(vector.get("maxRetries", 2))})
		if vector.get("cacheAvailable", false):
			Client._write_text(client._cache_path(KEY), JSON.stringify({"token":_vectors.graceTokenVectors[0].token}))
		var result: Variant
		match vector.operation:
			"validate": result = await client.validate(KEY, "1.0", PRODUCT)
			"activate": result = await client.activate(KEY, DEVICE, "Fictional desktop", "1.0", PRODUCT)
			"checkout": result = await client.checkout(KEY, DEVICE)
			"heartbeat": result = await client.heartbeat("test-session")
			"deactivate": result = await client.deactivate("qa-tenant", KEY, "test-activation")
			"meter": result = await client.meter(KEY, "test-meter")
			"checkin": result = await client.try_checkin("test-session")
		if result is bool:
			_check(result == vector.expectedSuccess, id + "/success")
		elif result is Types.LicenseResult:
			_check(result.is_valid == vector.expectedSuccess and result.error_code == vector.expectedErrorCode and result.is_offline == vector.expectedOffline, id)
		else:
			_check(result.success == vector.expectedSuccess and result.error_code == vector.expectedErrorCode, id)

func _security_cases(security: Dictionary) -> void:
	for vector in security.graceCases:
		var client := _client("security-cache", {"trusted_public_keys":[security.pin], "cache_directory":_cache_root.path_join("security-" + str(vector.name).sha256_text())})
		Client._write_text(client._cache_path(KEY), JSON.stringify({"token":vector.token, "publicKey":security.get("attackerPin")}))
		var validated := await client.validate(KEY, "1.0", PRODUCT)
		_check(validated.is_valid == vector.validate, "signed context validate/" + vector.name)
		var activated := await client.activate(KEY, DEVICE, "Fictional desktop", "1.0", PRODUCT)
		_check(activated.is_valid == vector.activate, "signed context activate/" + vector.name)
	var pinned := _client("security-cache", {"trusted_public_keys":[security.pin]})
	Client._write_text(pinned._cache_path(KEY), JSON.stringify({"token":security.validGrace}))
	var unpinned := _client("security-cache", {"trusted_public_keys":[]})
	_check(not (await unpinned.validate(KEY, "1.0", PRODUCT)).is_valid, "cache cannot supply trust")
	var rotated := _client("security-cache", {"trusted_public_keys":[security.attackerPin, security.pin]})
	_check((await rotated.validate(KEY, "1.0", PRODUCT)).is_valid, "configured trust rotation")
	Client._write_text(pinned._cache_path(KEY), JSON.stringify({"isValid":true,"productId":PRODUCT,"publicKey":security.pin}))
	_check(not (await pinned.validate(KEY, "1.0", PRODUCT)).is_valid, "unsigned cache rejected")
	_check(pinned.activate_offline(security.manual, DEVICE, PRODUCT).is_valid, "independent signed manual proof")
	var stored: Dictionary = JSON.parse_string(FileAccess.get_file_as_string(pinned._offline_path(DEVICE)))
	_check(stored.keys() == ["token"] and stored.token == security.manual, "manual cache stores only original token")
	Client._write_text(pinned._offline_path(DEVICE), JSON.stringify({"isValid":true,"deviceId":DEVICE}))
	_check(not pinned.validate_offline(DEVICE, PRODUCT).is_valid, "manual cache reverified")
	_check((await _client("offline-online-valid").verify_offline_online(security.manual)).is_valid, "online token verification")
	_check(not (await _client("offline-online-denied").verify_offline_online(security.manual)).is_valid, "online token HTTP authority")
	var tls_client := Client.new(security.tlsUrl, {"tls_ca_file":security.caFile, "enable_offline_cache":false, "timeout_seconds":1.0, "max_retries":0})
	var tls_result := await tls_client.validate(KEY, "1.0", PRODUCT)
	_check(tls_result.is_valid, "TLS trusted CA and hostname: " + tls_result.error_code + "/" + tls_client.configuration_error)
	var wrong_host := Client.new(security.wrongHostUrl, {"tls_ca_file":security.caFile, "enable_offline_cache":false, "timeout_seconds":1.0, "max_retries":0})
	_check(not (await wrong_host.validate(KEY, "1.0", PRODUCT)).is_valid, "TLS rejects wrong hostname")
	var wrong_ca := Client.new(security.tlsUrl, {"enable_offline_cache":false, "timeout_seconds":1.0, "max_retries":0})
	_check(not (await wrong_ca.validate(KEY, "1.0", PRODUCT)).is_valid, "TLS rejects untrusted CA")
	var before := Engine.get_process_frames()
	var started := Time.get_ticks_msec()
	Engine.time_scale = 0.0
	var timeout := await _client("timeout", {"timeout_seconds":0.1, "max_retries":1}).validate(KEY, "1.0", PRODUCT)
	Engine.time_scale = 1.0
	_check(not timeout.is_valid and timeout.error_code == "RequestFailed", "bounded attempt timeout")
	_check(Time.get_ticks_msec() - started < 1000 and Engine.get_process_frames() > before + 5, "request and retry do not block paused game loop")
