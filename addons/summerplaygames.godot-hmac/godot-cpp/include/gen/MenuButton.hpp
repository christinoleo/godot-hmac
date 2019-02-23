#ifndef GODOT_CPP_MENUBUTTON_HPP
#define GODOT_CPP_MENUBUTTON_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Button.hpp"
namespace godot {

class PopupMenu;
class InputEvent;

class MenuButton : public Button {
public:

	static inline const char *___get_class_name() { return (const char *) "MenuButton"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static MenuButton *_new();

	// methods
	PopupMenu *get_popup() const;
	void _unhandled_key_input(const Ref<InputEvent> arg0);
	void _set_items(const Array arg0);
	Array _get_items() const;
	void set_disable_shortcuts(const bool disabled);

};

}

#endif