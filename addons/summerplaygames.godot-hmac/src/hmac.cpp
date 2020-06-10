#include "hmac.hpp"

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

using namespace godot;

void HMAC::_register_methods() {
    register_method("digest", &HMAC::digest);
    register_method("hexdigest", &HMAC::hexdigest);
}

String HMAC::hexdigest(PoolByteArray secret, PoolByteArray payload, String type) {
    unsigned char localMac[32];

    const size_t keyLength = secret.size();
    const size_t payloadLength = payload.size();

    char* secretBuffer = new char[keyLength]();
    char* payloadBuffer = new char[payloadLength]();

    for (int i = 0; i < keyLength; i++) {
        secretBuffer[i] = (char)secret[i];
    }

    for (int i = 0; i < payloadLength; i++) {
        payloadBuffer[i] = (char)payload[i];
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_type_t mbedType = getMbedType(type.to_lower());
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(mbedType), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*) secretBuffer, keyLength);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)payloadBuffer, payloadLength);
    mbedtls_md_hmac_finish(&ctx, localMac);
    mbedtls_md_free(&ctx);

	char* convertedMac = bin2hex(localMac, sizeof(localMac));

    delete[] secretBuffer;
    delete[] payloadBuffer;

    return String(convertedMac);
}

PoolByteArray HMAC::digest(PoolByteArray secret, PoolByteArray payload, String type) {
    unsigned char localMac[32];

    const size_t keyLength = secret.size();
    const size_t payloadLength = payload.size();

    char* secretBuffer = new char[keyLength]();
    char* payloadBuffer = new char[payloadLength]();

    for (int i = 0; i < keyLength; i++) {
        secretBuffer[i] = (char)secret[i];
    }

    for (int i = 0; i < payloadLength; i++) {
        payloadBuffer[i] = (char)payload[i];
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_type_t mbedType = getMbedType(type.to_lower());
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(mbedType), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*) secretBuffer, keyLength);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)payloadBuffer, payloadLength);
    mbedtls_md_hmac_finish(&ctx, localMac);
    mbedtls_md_free(&ctx);

    PoolByteArray convertedMac = PoolByteArray();
    for(int i = 0; i < sizeof(localMac); i++){
        convertedMac.append(localMac[i]);
    }

    delete[] secretBuffer;
    delete[] payloadBuffer;

    return convertedMac;
}

char* HMAC::bin2hex(const unsigned char *bin, size_t len){
	char *out;
	size_t  i;

	if (bin == NULL || len == 0)
		return NULL;

	out = (char*)malloc(len*2+1);
	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
		out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';

	return out;
}


mbedtls_md_type_t HMAC::getMbedType(String type) {
    if (type == "sha256") { return MBEDTLS_MD_SHA256; }
	else if(type == "none") { return MBEDTLS_MD_NONE;}
	else if(type == "md2") { return MBEDTLS_MD_MD2;}
	else if(type == "md4") { return MBEDTLS_MD_MD4;}
	else if(type == "md5") { return MBEDTLS_MD_MD5;}
	else if(type == "sha1") { return MBEDTLS_MD_SHA1;}
	else if(type == "sha224") { return MBEDTLS_MD_SHA224;}
	else if(type == "sha384") { return MBEDTLS_MD_SHA384;}
	else if(type == "sha512") { return MBEDTLS_MD_SHA512;}
	else if(type == "ripemd160") { return MBEDTLS_MD_RIPEMD160;}
    return MBEDTLS_MD_SHA256;
}

HMAC::HMAC() {}

HMAC::~HMAC() {}

void HMAC::_init() {
    
}

