#include "CanvasModulate.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"




namespace godot {


CanvasModulate *CanvasModulate::_new()
{
	return (CanvasModulate *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, godot::api->godot_get_class_constructor((char *)"CanvasModulate")());
}
void CanvasModulate::set_color(const Color color) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("CanvasModulate", "set_color");
	}
	___godot_icall_void_Color(mb, (const Object *) this, color);
}

Color CanvasModulate::get_color() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("CanvasModulate", "get_color");
	}
	return ___godot_icall_Color(mb, (const Object *) this);
}

}