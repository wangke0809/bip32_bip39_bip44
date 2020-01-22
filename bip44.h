#ifndef SKYCOIN_CRYPTO_BIP44_H
#define SKYCOIN_CRYPTO_BIP44_H

#include <stddef.h>
#include <stdint.h>

//int hdnode_ckd_address_from_path(const uint8_t* seed, size_t seed_len, const char* path, uint8_t* out_addrs, size_t* out_addrs_size);

//int hdnode_address_for_branch(const uint8_t* seed, size_t seed_len, uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index, char* out_addrs, size_t* out_addrs_size);

//int hdnode_keypair_for_branch(const uint8_t* seed, size_t seed_len, uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index, uint8_t* seckey, uint8_t* pubkey);

int hdnode_ckd_keypair_from_path(const uint8_t* seed, size_t seed_len, const char* path, uint8_t* prikey, uint8_t* pubkey);

#endif // SKYCOIN_CRYPTO_BIP44_H
