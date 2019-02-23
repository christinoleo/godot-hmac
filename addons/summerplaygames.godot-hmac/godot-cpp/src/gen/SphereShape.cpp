#include "SphereShape.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"




namespace godot {


SphereShape *SphereShape::_new()
{
	return (SphereShape *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, godot::api->godot_get_class_constructor((char *)"SphereShape")());
}
void SphereShape::set_radius(const double radius) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("SphereShape", "set_radius");
	}
	___godot_icall_void_float(mb, (const Object *) this, radius);
}

double SphereShape::get_radius() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("SphereShape", "get_radius");
	}
	return ___godot_icall_float(mb, (const Object *) this);
}

}