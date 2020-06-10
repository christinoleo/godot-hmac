#ifndef HMAC_HPP
#define HMAC_HPP

#include <Godot.hpp>
#include <Node.hpp>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

namespace godot {
    class HMAC : public Node {
        GODOT_CLASS(HMAC, Node)
    
    private:
        mbedtls_md_type_t getMbedType(String type);
	    char* bin2hex(const unsigned char *bin, size_t len);

    public:
        static void _register_methods();
        PoolByteArray digest(PoolByteArray secret, PoolByteArray payload, String type);
        String hexdigest(PoolByteArray secret, PoolByteArray payload, String type);

        HMAC();
        ~HMAC();

        void _init();
    };
}

#endif