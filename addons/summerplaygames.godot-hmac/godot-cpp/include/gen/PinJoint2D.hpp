#ifndef GODOT_CPP_PINJOINT2D_HPP
#define GODOT_CPP_PINJOINT2D_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Joint2D.hpp"
namespace godot {


class PinJoint2D : public Joint2D {
public:

	static inline const char *___get_class_name() { return (const char *) "PinJoint2D"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static PinJoint2D *_new();

	// methods
	void set_softness(const double softness);
	double get_softness() const;

};

}

#endif