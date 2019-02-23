#ifndef GODOT_CPP_VISUALSCRIPTFUNCTIONSTATE_HPP
#define GODOT_CPP_VISUALSCRIPTFUNCTIONSTATE_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Reference.hpp"
namespace godot {

class Object;

class VisualScriptFunctionState : public Reference {
public:

	static inline const char *___get_class_name() { return (const char *) "VisualScriptFunctionState"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static VisualScriptFunctionState *_new();

	// methods
	void connect_to_signal(const Object *obj, const String signals, const Array args);
	Variant resume(const Array args = Array());
	bool is_valid() const;
	Variant _signal_callback(const Array& __var_args = Array());
	template <class... Args> Variant _signal_callback(Args... args){
		return _signal_callback(Array::make(args...));
	}

};

}

#endif