#ifndef GODOT_CPP_ATLASTEXTURE_HPP
#define GODOT_CPP_ATLASTEXTURE_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "Texture.hpp"
namespace godot {

class Texture;

class AtlasTexture : public Texture {
public:

	static inline const char *___get_class_name() { return (const char *) "AtlasTexture"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static AtlasTexture *_new();

	// methods
	void set_atlas(const Ref<Texture> atlas);
	Ref<Texture> get_atlas() const;
	void set_region(const Rect2 region);
	Rect2 get_region() const;
	void set_margin(const Rect2 margin);
	Rect2 get_margin() const;
	void set_filter_clip(const bool enable);
	bool has_filter_clip() const;

};

}

#endif