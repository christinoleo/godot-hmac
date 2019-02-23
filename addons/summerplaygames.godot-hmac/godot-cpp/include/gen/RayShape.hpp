#ifndef GODOT_CPP_RAYSHAPE_HPP
#define GODOT_CPP_RAYSHAPE_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Shape.hpp"
namespace godot {


class RayShape : public Shape {
public:

	static inline const char *___get_class_name() { return (const char *) "RayShape"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static RayShape *_new();

	// methods
	void set_length(const double length);
	double get_length() const;
	void set_slips_on_slope(const bool active);
	bool get_slips_on_slope() const;

};

}

#endif