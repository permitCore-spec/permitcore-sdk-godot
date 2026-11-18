extends RefCounted
## Godot-native, frame-polled HTTP. Retain captured status even if the body is truncated.
## HTTPClient never follows redirects. TLSOptions.client keeps CA/hostname verification.
const BODY_LIMIT := 4 * 1024 * 1024

static func request(tree: SceneTree, url: String, method: HTTPClient.Method, payload: Variant, timeout_seconds: float, tls_ca: X509Certificate = null) -> Dictionary:
	var regex := RegEx.new()
	regex.compile("^(https?)://(\\[[0-9A-Fa-f:]+\\]|[^/:?#\\s]+)(?::([0-9]{1,5}))?(/[^?#]*)?$")
	var match := regex.search(url)
	if match == null:
		return _finish(0, PackedByteArray(), false)
	var secure := match.get_string(1) == "https"
	var host := match.get_string(2).trim_prefix("[").trim_suffix("]")
	var port := match.get_string(3).to_int() if not match.get_string(3).is_empty() else (443 if secure else 80)
	var path := match.get_string(4) if not match.get_string(4).is_empty() else "/"
	var http := HTTPClient.new()
	var deadline := Time.get_ticks_msec() + int(timeout_seconds * 1000)
	if http.connect_to_host(host, port, TLSOptions.client(tls_ca) if secure else null) != OK:
		return _finish(0, PackedByteArray(), false)
	while http.get_status() in [HTTPClient.STATUS_RESOLVING, HTTPClient.STATUS_CONNECTING]:
		http.poll()
		if Time.get_ticks_msec() >= deadline:
			http.close()
			return _finish(0, PackedByteArray(), false)
		await tree.process_frame
	if http.get_status() != HTTPClient.STATUS_CONNECTED:
		http.close()
		return _finish(0, PackedByteArray(), false)
	var headers := PackedStringArray(["User-Agent: PermitCore-Godot/2.2.0", "Accept: application/json", "Accept-Encoding: identity"])
	var body := ""
	if payload != null:
		headers.append("Content-Type: application/json")
		body = JSON.stringify(payload)
	if http.request(method, path, headers, body) != OK:
		http.close()
		return _finish(0, PackedByteArray(), false)
	var status := 0
	var bytes := PackedByteArray()
	var expected_length := -1
	var captured := false
	while Time.get_ticks_msec() < deadline:
		var error := http.poll()
		if not captured and http.has_response():
			status = http.get_response_code()
			expected_length = http.get_response_body_length()
			captured = true
		var state := http.get_status()
		if state == HTTPClient.STATUS_BODY:
			bytes.append_array(http.read_response_body_chunk())
			if bytes.size() > BODY_LIMIT:
				http.close()
				return _finish(status, PackedByteArray(), false)
			if expected_length >= 0 and bytes.size() == expected_length:
				http.close()
				return _finish(status, bytes, true)
		elif captured:
			http.close()
			return _finish(status, bytes, status == 204 or expected_length >= 0 and bytes.size() == expected_length or expected_length < 0 and error == OK)
		elif error != OK or state != HTTPClient.STATUS_REQUESTING:
			http.close()
			return _finish(status, bytes, false)
		await tree.process_frame
	http.close()
	return _finish(status, bytes, false)

static func _finish(status: int, bytes: PackedByteArray, complete: bool) -> Dictionary:
	var json := JSON.new()
	var parsed := json.parse(bytes.get_string_from_utf8())
	var data: Variant = json.data if parsed == OK else null
	if status >= 300 and status < 500:
		return {"kind":"http", "status":status, "data":data if complete else null}
	if status >= 500 or status == 0:
		return {"kind":"transient", "status":status, "data":null}
	if status >= 200 and status < 300:
		if not complete or status != 204 and parsed != OK:
			return {"kind":"invalid", "status":status, "data":null}
		return {"kind":"ok", "status":status, "data":data}
	return {"kind":"transient", "status":status, "data":null}
