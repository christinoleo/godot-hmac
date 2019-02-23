#include "VisualScriptVariableSet.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"




namespace godot {


VisualScriptVariableSet *VisualScriptVariableSet::_new()
{
	return (VisualScriptVariableSet *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, godot::api->godot_get_class_constructor((char *)"VisualScriptVariableSet")());
}
void VisualScriptVariableSet::set_variable(const String name) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("VisualScriptVariableSet", "set_variable");
	}
	___godot_icall_void_String(mb, (const Object *) this, name);
}

String VisualScriptVariableSet::get_variable() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("VisualScriptVariableSet", "get_variable");
	}
	return ___godot_icall_String(mb, (const Object *) this);
}

}