#ifndef GODOT_CPP_BONEATTACHMENT_HPP
#define GODOT_CPP_BONEATTACHMENT_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Spatial.hpp"
namespace godot {


class BoneAttachment : public Spatial {
public:

	static inline const char *___get_class_name() { return (const char *) "BoneAttachment"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static BoneAttachment *_new();

	// methods
	void set_bone_name(const String bone_name);
	String get_bone_name() const;

};

}

#endif