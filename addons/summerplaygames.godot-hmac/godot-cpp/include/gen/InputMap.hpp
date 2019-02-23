#ifndef GODOT_CPP_INPUTMAP_HPP
#define GODOT_CPP_INPUTMAP_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Object.hpp"
namespace godot {

class InputEvent;

class InputMap : public Object {
	static InputMap *_singleton;

	InputMap();

public:

	static inline InputMap *get_singleton()
	{
		if (!InputMap::_singleton) {
			InputMap::_singleton = new InputMap;
		}
		return InputMap::_singleton;
	}

	static inline const char *___get_class_name() { return (const char *) "InputMap"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants

	// methods
	bool has_action(const String action) const;
	Array get_actions();
	void add_action(const String action, const double deadzone = 0.5);
	void erase_action(const String action);
	void action_set_deadzone(const String action, const double deadzone);
	void action_add_event(const String action, const Ref<InputEvent> event);
	bool action_has_event(const String action, const Ref<InputEvent> event);
	void action_erase_event(const String action, const Ref<InputEvent> event);
	void action_erase_events(const String action);
	Array get_action_list(const String action);
	bool event_is_action(const Ref<InputEvent> event, const String action) const;
	void load_from_globals();

};

}

#endif