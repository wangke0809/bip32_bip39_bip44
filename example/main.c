//
// Created by Adebayo Olabode on 11/5/18.
//

#include "main.h"
#include <stdio.h>


int main(void){

    // generate mnmemoic
    const char *passphrase ="";
    int strength = 128;
    int keylength = 64;
    //3,6,9,12,15,18,21,24
    //int numwords = 6;
    //this generates the mnemonic
//    const char *mnemonic = generateMnemonic(strength);

    const char *mnemonic = "taste exercise obscure gospel rude kidney suffer seminar awkward almost festival wave spider manage shallow";
    printf("Mnemonic string : %s \n",mnemonic);
    uint8_t bip39_seed[keylength];
    //this generates a bip39 seed from mnemonic
    generateBip39Seeed(mnemonic,bip39_seed,passphrase);
    print_hex(bip39_seed);
    char rootkey[112];
    uint32_t fingerprint = 0;
    HDNode node;
    //generateBip32RootKey(bip39_seed,rootkey);
    //printf("root key:%s\n",rootkey);
    hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &node);
    hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE, rootkey, sizeof(rootkey));
    printf("root key:%s\n",rootkey);

    uint8_t addr[100];
    size_t addr_size = sizeof(addr);
    char path[] = {"m/44'/0'/0'/0/0"};
    addr_size = sizeof(addr);
    uint8_t private_key[32];
    uint8_t public_key[33];
    int ret = hdnode_ckd_keypair_from_path(bip39_seed, keylength, path, private_key, public_key);
    printf("ret %d\r\n", ret);

    for(size_t i = 0; i < 32; i++) {
        printf("%02x", private_key[i]);
    }
    printf("\n");

    for(size_t i = 0; i < 33; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");

//    int hdnode_sign_digest(HDNode *node, const uint8_t *digest, uint8_t *sig, uint8_t *pby, int (*is_canonical)(uint8_t by, uint8_t sig[64]))

    HDNode node2;
    hdnode_for_sign_from_private_key((const uint8_t *)private_key, SECP256K1_NAME, &node2);
    uint8_t digest[32] = {0};
    uint8_t sig[64];
    hdnode_sign_digest(&node2, digest, sig, NULL, NULL);

    for(size_t i = 0; i < 64; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");
}