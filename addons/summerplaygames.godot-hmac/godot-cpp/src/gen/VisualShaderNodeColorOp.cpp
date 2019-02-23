#include "VisualShaderNodeColorOp.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"




namespace godot {


VisualShaderNodeColorOp *VisualShaderNodeColorOp::_new()
{
	return (VisualShaderNodeColorOp *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, godot::api->godot_get_class_constructor((char *)"VisualShaderNodeColorOp")());
}
void VisualShaderNodeColorOp::set_operator(const int64_t op) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("VisualShaderNodeColorOp", "set_operator");
	}
	___godot_icall_void_int(mb, (const Object *) this, op);
}

VisualShaderNodeColorOp::Operator VisualShaderNodeColorOp::get_operator() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("VisualShaderNodeColorOp", "get_operator");
	}
	return (VisualShaderNodeColorOp::Operator) ___godot_icall_int(mb, (const Object *) this);
}

}