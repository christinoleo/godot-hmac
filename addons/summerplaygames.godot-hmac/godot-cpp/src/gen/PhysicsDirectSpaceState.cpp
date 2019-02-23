#include "PhysicsDirectSpaceState.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"


#include "PhysicsShapeQueryParameters.hpp"


namespace godot {


Dictionary PhysicsDirectSpaceState::intersect_ray(const Vector3 from, const Vector3 to, const Array exclude, const int64_t collision_mask, const bool collide_with_bodies, const bool collide_with_areas) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("PhysicsDirectSpaceState", "intersect_ray");
	}
	return ___godot_icall_Dictionary_Vector3_Vector3_Array_int_bool_bool(mb, (const Object *) this, from, to, exclude, collision_mask, collide_with_bodies, collide_with_areas);
}

Array PhysicsDirectSpaceState::intersect_shape(const Ref<PhysicsShapeQueryParameters> shape, const int64_t max_results) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("PhysicsDirectSpaceState", "intersect_shape");
	}
	return ___godot_icall_Array_Object_int(mb, (const Object *) this, shape.ptr(), max_results);
}

Array PhysicsDirectSpaceState::cast_motion(const Ref<PhysicsShapeQueryParameters> shape, const Vector3 motion) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("PhysicsDirectSpaceState", "cast_motion");
	}
	return ___godot_icall_Array_Object_Vector3(mb, (const Object *) this, shape.ptr(), motion);
}

Array PhysicsDirectSpaceState::collide_shape(const Ref<PhysicsShapeQueryParameters> shape, const int64_t max_results) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("PhysicsDirectSpaceState", "collide_shape");
	}
	return ___godot_icall_Array_Object_int(mb, (const Object *) this, shape.ptr(), max_results);
}

Dictionary PhysicsDirectSpaceState::get_rest_info(const Ref<PhysicsShapeQueryParameters> shape) {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("PhysicsDirectSpaceState", "get_rest_info");
	}
	return ___godot_icall_Dictionary_Object(mb, (const Object *) this, shape.ptr());
}

}