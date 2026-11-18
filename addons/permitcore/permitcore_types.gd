class_name PermitCoreTypes
extends RefCounted
## Result models retain the original API fields in data for forward compatibility.

class LicenseResult:
	extends RefCounted
	var is_valid: bool = false
	var is_offline: bool = false
	var product_id: String = ""
	var product_name: String = ""
	var message: String = ""
	var error_code: String = ""
	var remaining_activations: Variant = null
	var expires_at: Variant = null
	var maintenance_expires_at: Variant = null
	var features: Array = []
	var custom_fields: Dictionary = {}
	var vendor_warning: String = ""
	var payment_status: Variant = null
	var is_in_grace_period: bool = false
	var is_trial: bool = false
	var trial_days_remaining: Variant = null
	var node_locked: bool = false
	var offline_grace_days: Variant = null
	var min_version: Variant = null
	var max_version: Variant = null
	var offline_cache_token: String = ""
	var data: Dictionary = {}

	func has_feature(feature: String) -> bool:
		for item in features:
			if item is String and item.to_lower() == feature.to_lower():
				return true
		return false

	static func from_wire(value: Dictionary) -> LicenseResult:
		var result := LicenseResult.new()
		result.data = value.duplicate(true)
		result.is_valid = value.get("isValid") is bool and value.get("isValid") == true
		result.is_offline = value.get("isOffline") == true
		var strings := {"product_id":"productId", "product_name":"productName", "message":"message", "error_code":"errorCode", "vendor_warning":"vendorWarning", "offline_cache_token":"offlineCacheToken"}
		for binding in strings:
			var field: Variant = value.get(strings[binding])
			if field is String:
				result.set(binding, field)
		var optional := {"remaining_activations":"remainingActivations", "expires_at":"expiresAt", "maintenance_expires_at":"maintenanceExpiresAt", "payment_status":"paymentStatus", "trial_days_remaining":"trialDaysRemaining", "offline_grace_days":"offlineGraceDays", "min_version":"minVersion", "max_version":"maxVersion"}
		for binding in optional:
			result.set(binding, value.get(optional[binding]))
		var flags := {"is_in_grace_period":"isInGracePeriod", "is_trial":"isTrial", "node_locked":"nodeLocked"}
		for binding in flags:
			result.set(binding, value.get(flags[binding]) == true)
		if value.get("features") is Array:
			result.features = value.features.duplicate(true)
		if value.get("customFields") is Dictionary:
			result.custom_fields = value.customFields.duplicate(true)
		return result

class FloatingSession:
	extends RefCounted
	var success: bool = false
	var session_token: String = ""
	var expires_at: String = ""
	var message: String = ""
	var error_code: String = ""

class TokenResult:
	extends RefCounted
	var is_valid: bool = false
	var message: String = ""
	var payload: Dictionary = {}
	var is_revoked: bool = false
	var data: Dictionary = {}
