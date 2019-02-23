#ifndef GODOT_CPP_VISUALSCRIPTLOCALVARSET_HPP
#define GODOT_CPP_VISUALSCRIPTLOCALVARSET_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include "Variant.hpp"

#include "VisualScriptNode.hpp"
namespace godot {


class VisualScriptLocalVarSet : public VisualScriptNode {
public:

	static inline const char *___get_class_name() { return (const char *) "VisualScriptLocalVarSet"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static VisualScriptLocalVarSet *_new();

	// methods
	void set_var_name(const String name);
	String get_var_name() const;
	void set_var_type(const int64_t type);
	Variant::Type get_var_type() const;

};

}

#endif