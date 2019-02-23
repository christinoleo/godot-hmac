#ifndef GODOT_CPP_CIRCLESHAPE2D_HPP
#define GODOT_CPP_CIRCLESHAPE2D_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Shape2D.hpp"
namespace godot {


class CircleShape2D : public Shape2D {
public:

	static inline const char *___get_class_name() { return (const char *) "CircleShape2D"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static CircleShape2D *_new();

	// methods
	void set_radius(const double radius);
	double get_radius() const;

};

}

#endif