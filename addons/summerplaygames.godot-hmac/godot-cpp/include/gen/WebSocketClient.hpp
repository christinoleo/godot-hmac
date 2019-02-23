#ifndef GODOT_CPP_WEBSOCKETCLIENT_HPP
#define GODOT_CPP_WEBSOCKETCLIENT_HPP


#include <gdnative_api_struct.gen.h>
#include <stdint.h>

#include <core/CoreTypes.hpp>
#include <core/Ref.hpp>

#include "WebSocketMultiplayerPeer.hpp"
namespace godot {


class WebSocketClient : public WebSocketMultiplayerPeer {
public:

	static inline const char *___get_class_name() { return (const char *) "WebSocketClient"; }
	static inline Object *___get_from_variant(Variant a) { godot_object *o = (godot_object*) a; return (o) ? (Object *) godot::nativescript_1_1_api->godot_nativescript_get_instance_binding_data(godot::_RegisterState::language_index, o) : nullptr; }

	// enums

	// constants


	static WebSocketClient *_new();

	// methods
	Error connect_to_url(const String url, const PoolStringArray protocols = PoolStringArray(), const bool gd_mp_api = false);
	void disconnect_from_host(const int64_t code = 1000, const String reason = "");
	void set_verify_ssl_enabled(const bool enabled);
	bool is_verify_ssl_enabled() const;

};

}

#endif