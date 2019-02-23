#ifndef GODOT_CPP_INPUTEVENTMOUSEBUTTON_HPP
#define GODOT_CPP_INPUTEVENTMOUSEBUTTON_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "InputEventMouse.hpp"
namespace godot {


class InputEventMouseButton : public InputEventMouse {
public:

	static inline const char *___get_class_name() { return (const char *) "InputEventMouseButton"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static InputEventMouseButton *_new();

	// methods
	void set_factor(const double factor);
	double get_factor();
	void set_button_index(const int64_t button_index);
	int64_t get_button_index() const;
	void set_pressed(const bool pressed);
	void set_doubleclick(const bool doubleclick);
	bool is_doubleclick() const;

};

}

#endif