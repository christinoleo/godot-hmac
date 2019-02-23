#include "EditorSettings.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"




namespace godot {


bool EditorSettings::has_setting(const String name) const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "has_setting");
	}
	return ___godot_icall_bool_String(mb, (const Object *) this, name);
}

void EditorSettings::set_setting(const String name, const Variant value) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "set_setting");
	}
	___godot_icall_void_String_Variant(mb, (const Object *) this, name, value);
}

Variant EditorSettings::get_setting(const String name) const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "get_setting");
	}
	return ___godot_icall_Variant_String(mb, (const Object *) this, name);
}

void EditorSettings::erase(const String property) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "erase");
	}
	___godot_icall_void_String(mb, (const Object *) this, property);
}

void EditorSettings::set_initial_value(const String name, const Variant value, const bool update_current) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "set_initial_value");
	}
	___godot_icall_void_String_Variant_bool(mb, (const Object *) this, name, value, update_current);
}

bool EditorSettings::property_can_revert(const String name) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "property_can_revert");
	}
	return ___godot_icall_bool_String(mb, (const Object *) this, name);
}

Variant EditorSettings::property_get_revert(const String name) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "property_get_revert");
	}
	return ___godot_icall_Variant_String(mb, (const Object *) this, name);
}

void EditorSettings::add_property_info(const Dictionary info) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "add_property_info");
	}
	___godot_icall_void_Dictionary(mb, (const Object *) this, info);
}

String EditorSettings::get_settings_dir() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "get_settings_dir");
	}
	return ___godot_icall_String(mb, (const Object *) this);
}

String EditorSettings::get_project_settings_dir() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "get_project_settings_dir");
	}
	return ___godot_icall_String(mb, (const Object *) this);
}

void EditorSettings::set_project_metadata(const String section, const String key, const Variant data) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "set_project_metadata");
	}
	___godot_icall_void_String_String_Variant(mb, (const Object *) this, section, key, data);
}

Variant EditorSettings::get_project_metadata(const String section, const String key, const Variant _default) const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "get_project_metadata");
	}
	return ___godot_icall_Variant_String_String_Variant(mb, (const Object *) this, section, key, _default);
}

void EditorSettings::set_favorites(const PoolStringArray dirs) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "set_favorites");
	}
	___godot_icall_void_PoolStringArray(mb, (const Object *) this, dirs);
}

PoolStringArray EditorSettings::get_favorites() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "get_favorites");
	}
	return ___godot_icall_PoolStringArray(mb, (const Object *) this);
}

void EditorSettings::set_recent_dirs(const PoolStringArray dirs) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "set_recent_dirs");
	}
	___godot_icall_void_PoolStringArray(mb, (const Object *) this, dirs);
}

PoolStringArray EditorSettings::get_recent_dirs() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("EditorSettings", "get_recent_dirs");
	}
	return ___godot_icall_PoolStringArray(mb, (const Object *) this);
}

}