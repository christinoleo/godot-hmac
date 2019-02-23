#include "KinematicCollision2D.hpp"


#include <core/GodotGlobal.hpp>
#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>
#include <core/Godot.hpp>

#include "__icalls.hpp"


#include "Object.hpp"


namespace godot {


KinematicCollision2D *KinematicCollision2D::_new()
{
	return (KinematicCollision2D *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, godot::api->godot_get_class_constructor((char *)"KinematicCollision2D")());
}
Vector2 KinematicCollision2D::get_position() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_position");
	}
	return ___godot_icall_Vector2(mb, (const Object *) this);
}

Vector2 KinematicCollision2D::get_normal() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_normal");
	}
	return ___godot_icall_Vector2(mb, (const Object *) this);
}

Vector2 KinematicCollision2D::get_travel() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_travel");
	}
	return ___godot_icall_Vector2(mb, (const Object *) this);
}

Vector2 KinematicCollision2D::get_remainder() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_remainder");
	}
	return ___godot_icall_Vector2(mb, (const Object *) this);
}

Object *KinematicCollision2D::get_local_shape() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_local_shape");
	}
	return (Object *) ___godot_icall_Object(mb, (const Object *) this);
}

Object *KinematicCollision2D::get_collider() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_collider");
	}
	return (Object *) ___godot_icall_Object(mb, (const Object *) this);
}

int64_t KinematicCollision2D::get_collider_id() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_collider_id");
	}
	return ___godot_icall_int(mb, (const Object *) this);
}

Object *KinematicCollision2D::get_collider_shape() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_collider_shape");
	}
	return (Object *) ___godot_icall_Object(mb, (const Object *) this);
}

int64_t KinematicCollision2D::get_collider_shape_index() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_collider_shape_index");
	}
	return ___godot_icall_int(mb, (const Object *) this);
}

Vector2 KinematicCollision2D::get_collider_velocity() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_collider_velocity");
	}
	return ___godot_icall_Vector2(mb, (const Object *) this);
}

Variant KinematicCollision2D::get_collider_metadata() const {
	static godot_method_bind *mb = nullptr;
	if (mb == nullptr) {
		mb = godot::api->godot_method_bind_get_method("KinematicCollision2D", "get_collider_metadata");
	}
	return ___godot_icall_Variant(mb, (const Object *) this);
}

}