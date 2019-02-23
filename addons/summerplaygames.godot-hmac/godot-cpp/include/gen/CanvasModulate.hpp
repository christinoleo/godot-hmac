#ifndef GODOT_CPP_CANVASMODULATE_HPP
#define GODOT_CPP_CANVASMODULATE_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Node2D.hpp"
namespace godot {


class CanvasModulate : public Node2D {
public:

	static inline const char *___get_class_name() { return (const char *) "CanvasModulate"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static CanvasModulate *_new();

	// methods
	void set_color(const Color color);
	Color get_color() const;

};

}

#endif