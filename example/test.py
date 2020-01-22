# pip install eth_utils
# pip install pycryptodome
# pip install coincurve
from eth_utils import big_endian_to_int
from Crypto.Hash import keccak
from coincurve import PrivateKey, PublicKey


def get_raw_signature(der_sig: bytes) -> bytes:
    if len(der_sig) < 70 or len(der_sig) > 72:
        return None

    struct_type = der_sig[0]
    if struct_type != 0x30:
        return None

    follow_len = der_sig[1]
    if follow_len < 0x44 or follow_len > 0x46:
        return None

    r_integer_sign = der_sig[2]
    if r_integer_sign != 0x02:
        return None

    r_len = der_sig[3]
    if r_len != 0x20 and r_len != 0x21:
        return None

    r = der_sig[4:4 + r_len]

    s_integer_sign = der_sig[4 + r_len]
    if s_integer_sign != 0x02:
        return None

    s_len = der_sig[5 + r_len]
    if s_len != 0x20 and s_len != 0x21:
        return None

    s = der_sig[6 + r_len:]

    if follow_len != (r_len + s_len + 4):
        return None

    if r_len == 0x21 and r[0] != 0x00:
        return None

    if s_len == 0x21 and s[0] != 0x00:
        return None

    strip_r = r if r_len == 0x20 else r[1:]
    strip_s = s if s_len == 0x20 else s[1:]
    print(strip_r.hex())
    print(strip_s.hex())
    return strip_r, strip_s


def test(full_pubkey, transaction_hash, signature):
    print('sign_transaction_hash:', transaction_hash.hex())
    r = signature[0:32]
    s = signature[32:64]
    v = None
    for v_i in range(4):
        signed_s = signature + bytes([v_i])
        try:
            public_key_bytes = PublicKey.from_signature_and_message(signed_s, transaction_hash, hasher=None).format(
                compressed=False)[1:]
            # print('rec', public_key_bytes.hex())
            if full_pubkey.hex() == public_key_bytes.hex():
                v = bytes([v_i])
                print('GET V!')
                break
        except Exception as e:
            # print(e)
            pass
    r = big_endian_to_int(r)
    s = big_endian_to_int(s)
    v = ord(v)
    print('signature_r_s_v:', signature.hex() + bytes([v]).hex())


if __name__ == '__main__':
    print(bytes([1, 2, 3]).hex())
    print(bytes.fromhex("010203"))
    sig = bytes.fromhex(
        "bde0c8ad6a050a773d963cdaec636be1da5807aed1d3f206f75b8c475934d80d6c5786e867c4bc8e5319fc4b356629d569894875f34857e9acfff847c006652d")

    key = 'b7741b1d53cdacea2e8f5bbf6164ca6c89fd932a26b3410b8f13f865cdbcd873'
    pk = PrivateKey(bytes.fromhex(key))
    full_pk_bytes = pk.public_key.format(False)[1:]
    print("pk:", full_pk_bytes.hex())
    hash = bytes.fromhex('00' * 32)
    test(full_pk_bytes, hash, sig)
