#include "SceneTreeTimer.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"




namespace godot {


void SceneTreeTimer::set_time_left(const double time) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("SceneTreeTimer", "set_time_left");
	}
	___godot_icall_void_float(mb, (const Object *) this, time);
}

double SceneTreeTimer::get_time_left() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("SceneTreeTimer", "get_time_left");
	}
	return ___godot_icall_float(mb, (const Object *) this);
}

}