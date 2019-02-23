#include "Font.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"




namespace godot {


void Font::draw(const RID canvas_item, const Vector2 position, const String string, const Color modulate, const int64_t clip_w, const Color outline_modulate) const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "draw");
	}
	___godot_icall_void_RID_Vector2_String_Color_int_Color(mb, (const Object *) this, canvas_item, position, string, modulate, clip_w, outline_modulate);
}

double Font::get_ascent() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "get_ascent");
	}
	return ___godot_icall_float(mb, (const Object *) this);
}

double Font::get_descent() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "get_descent");
	}
	return ___godot_icall_float(mb, (const Object *) this);
}

double Font::get_height() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "get_height");
	}
	return ___godot_icall_float(mb, (const Object *) this);
}

bool Font::is_distance_field_hint() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "is_distance_field_hint");
	}
	return ___godot_icall_bool(mb, (const Object *) this);
}

Vector2 Font::get_string_size(const String string) const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "get_string_size");
	}
	return ___godot_icall_Vector2_String(mb, (const Object *) this, string);
}

bool Font::has_outline() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "has_outline");
	}
	return ___godot_icall_bool(mb, (const Object *) this);
}

double Font::draw_char(const RID canvas_item, const Vector2 position, const int64_t _char, const int64_t next, const Color modulate, const bool outline) const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "draw_char");
	}
	return ___godot_icall_float_RID_Vector2_int_int_Color_bool(mb, (const Object *) this, canvas_item, position, _char, next, modulate, outline);
}

void Font::update_changes() {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("Font", "update_changes");
	}
	___godot_icall_void(mb, (const Object *) this);
}

}