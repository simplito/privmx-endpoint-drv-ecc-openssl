/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "privmx/drv/ecc.h"

struct privmxDrvEcc_BN {
    std::unique_ptr<BIGNUM, decltype(&BN_free)> impl;
};

struct privmxDrvEcc_Point {
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> impl;
};

struct privmxDrvEcc_ECC {
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> impl;
};


int privmxDrvEcc_version(unsigned int* version) {
    *version = 1;
    return 0;
}


int privmxDrvEcc_bnBin2bn(const char* bin, int binlen, privmxDrvEcc_BN** res) {
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(BN_new(), BN_free);
    if (bn.get() == NULL) {
        return 1;
    }
    if (BN_bin2bn(reinterpret_cast<const unsigned char*>(bin), binlen, bn.get()) == NULL) {
        return 2;
    }
    *res = new privmxDrvEcc_BN{move(bn)};
    return 0;
}

int privmxDrvEcc_bnBn2bin(privmxDrvEcc_BN* bn, char** out, int* outlen) {
    BIGNUM* _bn = bn->impl.get();
    int size = BN_num_bytes(_bn);
    unsigned char* result = (unsigned char*)malloc(size);
    BN_bn2bin(_bn, result);
    *out = (char*)result;
    *outlen = size;
    return 0;
}

int privmxDrvEcc_bnBitsLength(const privmxDrvEcc_BN* bn, int* res) {
    const BIGNUM* _bn = bn->impl.get();
    int size = BN_num_bits(_bn);
    *res = size;
    return 0;
}

int privmxDrvEcc_bnUmod(const privmxDrvEcc_BN* bn1, const privmxDrvEcc_BN* bn2, privmxDrvEcc_BN** res) {
    const BIGNUM* _bn1 = bn1->impl.get();
    const BIGNUM* _bn2 = bn2->impl.get();
    std::unique_ptr<BIGNUM, decltype(&BN_free)> _res(BN_new(), BN_free);
    if (_res.get() == NULL) {
        return 1;
    }
    std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx.get() == NULL) {
        return 2;
    }
    if (!BN_nnmod(_res.get(), _bn1, _bn2, ctx.get())) {
        return 3;
    };
    *res = new privmxDrvEcc_BN{move(_res)};
    return 0;
}

int privmxDrvEcc_bnEq(const privmxDrvEcc_BN* bn1, const privmxDrvEcc_BN* bn2, int* res) {
    const BIGNUM* _bn1 = bn1->impl.get();
    const BIGNUM* _bn2 = bn2->impl.get();
    *res = (BN_cmp(_bn1, _bn2) == 0);
    return 0;
}

int privmxDrvEcc_bnCopy(const privmxDrvEcc_BN* src, privmxDrvEcc_BN** dst) {
    const BIGNUM* _src = src->impl.get();
    std::unique_ptr<BIGNUM, decltype(&BN_free)> _dst(BN_new(), BN_free);
    if (_dst.get() == NULL) {
        return 1;
    }
    if (BN_copy(_dst.get(), _src) == NULL) {
        return 2;
    }
    *dst = new privmxDrvEcc_BN{move(_dst)};
    return 0;
}

int privmxDrvEcc_bnNew(privmxDrvEcc_BN** res) {
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(BN_new(), BN_free);
    if (bn.get() == NULL) {
        return 1;
    }
    *res = new privmxDrvEcc_BN{move(bn)};
    return 0;
}

int privmxDrvEcc_bnFree(privmxDrvEcc_BN* bn) {
    delete bn;
    return 0;
}

using ec_point_unique_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using ec_group_unique_ptr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using bn_ctx_unique_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;

ec_group_unique_ptr getEcGroup() {
    ec_group_unique_ptr group(EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free);
    return group;
}

bn_ctx_unique_ptr newBnCtx() {
    bn_ctx_unique_ptr ctx(BN_CTX_new(), BN_CTX_free);
    return ctx;
}

ec_point_unique_ptr newEcPoint() {
    ec_group_unique_ptr group = getEcGroup();
    ec_point_unique_ptr point(EC_POINT_new(group.get()), EC_POINT_free);
    return point;
}

int privmxDrvEcc_pointOct2point(const char* oct, int octlen, privmxDrvEcc_Point** res) {
    ec_point_unique_ptr point = newEcPoint();
    if (point.get() == NULL) {
        return 1;
    }
    ec_group_unique_ptr group = getEcGroup();
    if (group == NULL) {
        return 2;
    }
    bn_ctx_unique_ptr ctx = newBnCtx();
    if (ctx = NULL) {
        return 3;
    }
    EC_POINT* raw_point = point.get();
    BN_CTX* raw_ctx = ctx.get();
    if (EC_POINT_oct2point(group.get(), raw_point, reinterpret_cast<const unsigned char*>(oct), octlen, raw_ctx) == 0) {
        return 4;
    }
    *res = new privmxDrvEcc_Point{move(point)};
    return 0;
}

int privmxDrvEcc_pointEncode(const privmxDrvEcc_Point* point, int compact, char** out, int* outlen) {
    const EC_POINT* _point = point->impl.get();
    if (!_point) {
        return 1;
    }
    ec_group_unique_ptr group = getEcGroup();
    point_conversion_form_t form = compact ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    size_t size = EC_POINT_point2oct(group.get(), _point, form, NULL, 0, NULL);
    if (size == 0) {
        return 1;
    }
    std::string result(size, 0);
    unsigned char* buf = reinterpret_cast<unsigned char*>(result.data());
    if (EC_POINT_point2oct(group.get(), _point, form, buf, size, NULL) == 0) {
        return 2;
    }
    char* tmp = (char*)malloc(size);
    memcpy(tmp, result.data(), size);
    *out = tmp;
    *outlen = size;
    return 0;
}

int privmxDrvEcc_pointMul(const privmxDrvEcc_Point* point, const privmxDrvEcc_BN* bn, privmxDrvEcc_Point** res) {
    const EC_POINT* _point = point->impl.get();
    const BIGNUM* _bn = (const BIGNUM*)_bn;
    if (!_point || !_bn) {
        return 1;
    }
    ec_point_unique_ptr new_point = newEcPoint();
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    if (EC_POINT_mul(group.get(), new_point.get(), NULL, _point, _bn, ctx.get()) == 0) {
        return 2;
    }
    *res = new privmxDrvEcc_Point{move(new_point)};
    return 0;
}

int privmxDrvEcc_pointAdd(const privmxDrvEcc_Point* point1, const privmxDrvEcc_Point* point2, privmxDrvEcc_Point** res) {
    const EC_POINT* _point1 = point1->impl.get();
    const EC_POINT* _point2 = point2->impl.get();
    if (!_point1 || !_point2) {
        return 1;
    }
    ec_group_unique_ptr group = getEcGroup();
    bn_ctx_unique_ptr ctx = newBnCtx();
    ec_point_unique_ptr new_point = newEcPoint();
    if (EC_POINT_add(group.get(), new_point.get(), _point1, _point2, ctx.get()) == 0) {
        return 2;
    }
    *res = new privmxDrvEcc_Point{move(new_point)};
    return 0;
}

int privmxDrvEcc_pointCopy(const privmxDrvEcc_Point* src, privmxDrvEcc_Point** dst) {
    const EC_POINT* _src = src->impl.get();
    if (!_src) {
        return 1;
    }
    ec_point_unique_ptr new_point = newEcPoint();
    EC_POINT* _dst = new_point.get();
    if (EC_POINT_copy(_dst, _src) == 0) {
        return 2;
    }
    *dst = new privmxDrvEcc_Point{move(new_point)};
    return 0;
}

int privmxDrvEcc_pointNew(privmxDrvEcc_Point** res) {
    ec_group_unique_ptr group = getEcGroup();
    ec_point_unique_ptr point(EC_POINT_new(group.get()), EC_POINT_free);
    if (point.get() == NULL) {
        return 1;
    }
    *res = new privmxDrvEcc_Point{move(point)};
    return 0;
}

int privmxDrvEcc_pointFree(privmxDrvEcc_Point* point) {
    delete point;
    return 0;
}

using ec_key_unique_ptr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using bignum_unique_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using bn_ctx_unique_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using ec_point_unique_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using ecdsa_sig_unique_ptr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
using ec_group_unique_ptr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;

ec_key_unique_ptr newEcKey() {
    ec_key_unique_ptr key(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
    return key;
}

bignum_unique_ptr newBignum() {
    bignum_unique_ptr bignum(BN_new(), BN_free);
    if (bignum.get() == NULL) {
        // OpenSSLUtils::handleErrors();
    }
    return bignum;
}

bignum_unique_ptr copyBignum(const BIGNUM* raw_bn) {
    if (!raw_bn) {
        return bignum_unique_ptr(nullptr, NULL);
    }
    bignum_unique_ptr bn = newBignum();
    BIGNUM* dst = bn.get();
    if (BN_copy(dst, raw_bn) == NULL) {
        // OpenSSLUtils::handleErrors();
    }
    return bn;
}

ec_point_unique_ptr copyEcPoint(const EC_POINT* raw_point, const EC_GROUP* group) {
    if (!raw_point) {
        return ec_point_unique_ptr(nullptr, NULL);
    }
    ec_point_unique_ptr new_point = newEcPoint();
    EC_POINT* dst = new_point.get();
    if (EC_POINT_copy(dst, raw_point) == 0) {
        // OpenSSLUtils::handleErrors();
    }
    return new_point;
}

// ec_point_unique_ptr newEcPoint(const EC_GROUP* group) {
//     ec_point_unique_ptr point(EC_POINT_new(group), EC_POINT_free);
//     if (point.get() == NULL) {
//         // OpenSSLUtils::handleErrors();
//     }
//     return point;
// }

void setPublicKey(const ec_key_unique_ptr& key, const ec_point_unique_ptr& public_point) {
    EC_KEY* raw_key = key.get();
    const EC_POINT* raw_public_point = public_point.get();
    if (EC_KEY_set_public_key(raw_key, raw_public_point) == 0) {
        // OpenSSLUtils::handleErrors();
    }
}

void setPrivateKey(const ec_key_unique_ptr& key, const bignum_unique_ptr& private_key) {
    EC_KEY* raw_key = key.get();
    const BIGNUM* raw_private_key = private_key.get();
    if (EC_KEY_set_private_key(raw_key, raw_private_key) == 0) {}
}

// void checkKey(const ec_key_unique_ptr& key) {
//     const EC_KEY* raw_key = key.get();
//     if (EC_KEY_check_key(raw_key) == 0) {
//         OpenSSLUtils::handleErrors();
//     }
// }

ec_point_unique_ptr mul(ec_key_unique_ptr& key) {
    const EC_KEY* raw_key = key.get();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const BIGNUM* raw_private_key = EC_KEY_get0_private_key(raw_key);
    bn_ctx_unique_ptr ctx = newBnCtx();
    BN_CTX* raw_ctx = ctx.get();
    ec_point_unique_ptr public_point = newEcPoint();
    EC_POINT* raw_public_point = public_point.get();
    if (EC_POINT_mul(group, raw_public_point, raw_private_key, NULL, NULL, raw_ctx) == 0) {
        // OpenSSLUtils::handleErrors();
    }
    return public_point;
}

bignum_unique_ptr bin2bignum(const std::string& bin) {
    const unsigned char* s = reinterpret_cast<const unsigned char*>(bin.data());
    int len = bin.size();
    bignum_unique_ptr bignum = newBignum();
    BIGNUM* raw_bignum = bignum.get();
    if (BN_bin2bn(s, len, raw_bignum) == NULL) {
        return bignum_unique_ptr(nullptr, NULL);
    }
    return bignum;
}

ec_point_unique_ptr oct2point(const ec_key_unique_ptr& key, const std::string& oct) {
    const EC_KEY* raw_key = key.get();
    const EC_GROUP* group = EC_KEY_get0_group(raw_key);
    const unsigned char* buf = reinterpret_cast<const unsigned char*>(oct.data());
    size_t len = oct.size();
    bn_ctx_unique_ptr ctx = newBnCtx();
    BN_CTX* raw_ctx = ctx.get();
    ec_point_unique_ptr public_point = newEcPoint();
    EC_POINT* raw_public_point = public_point.get();
    if (EC_POINT_oct2point(group, raw_public_point, buf, len, raw_ctx) == 0) {
        return ec_point_unique_ptr(nullptr, NULL);
    }
    return public_point;
}

int privmxDrvEcc_eccGenPair(privmxDrvEcc_ECC** res) {
    ec_key_unique_ptr key = newEcKey();
    if (EC_KEY_generate_key(key.get()) == 0) {
        return 1;
    }
    *res = new privmxDrvEcc_ECC{move(key)};
    return 0;
}

int privmxDrvEcc_eccFromPublicKey(const char* key, int keylen, privmxDrvEcc_ECC** res) {
    ec_key_unique_ptr new_key = newEcKey();
    ec_point_unique_ptr public_point = oct2point(new_key, std::string(key, keylen));
    if (public_point.get() == NULL) {
        return 1;
    }
    setPublicKey(new_key, public_point);
    const EC_KEY* raw_key = new_key.get();
    if (EC_KEY_check_key(raw_key) == 0) {
        return 2;
    }
    *res = new privmxDrvEcc_ECC{move(new_key)};
    return 0;
}

int privmxDrvEcc_eccFromPrivateKey(const char* key, int keylen, privmxDrvEcc_ECC** res) {
    ec_key_unique_ptr new_key = newEcKey();
    bignum_unique_ptr private_bn = bin2bignum(std::string(key, keylen));
    setPrivateKey(new_key, private_bn);
    ec_point_unique_ptr public_point = mul(new_key);
    setPublicKey(new_key, public_point);
    const EC_KEY* raw_key = new_key.get();
    if (EC_KEY_check_key(raw_key) == 0) {
        return 1;
    }
    *res = new privmxDrvEcc_ECC{move(new_key)};
    return 0;
}

int privmxDrvEcc_eccGetPublicKey(const privmxDrvEcc_ECC* ecc, privmxDrvEcc_Point** res) {
    const EC_KEY* _ecc = ecc->impl.get();
    const EC_POINT* public_point = EC_KEY_get0_public_key(_ecc);
    ec_point_unique_ptr new_point = newEcPoint();
    EC_POINT* _dst = new_point.get();
    if (EC_POINT_copy(_dst, public_point) == 0) {
        return 2;
    }
    *res = new privmxDrvEcc_Point{move(new_point)};
    return 0;
}

int privmxDrvEcc_eccGetPrivateKey(const privmxDrvEcc_ECC* ecc, privmxDrvEcc_BN** res) {
    const EC_KEY* _ecc = ecc->impl.get();
    const BIGNUM* priv = EC_KEY_get0_private_key(_ecc);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> _dst(BN_new(), BN_free);
    if (_dst.get() == NULL) {
        return 1;
    }
    if (BN_copy(_dst.get(), priv) == NULL) {
        return 2;
    }
    *res = new privmxDrvEcc_BN{move(_dst)};
    return 0;
}

int privmxDrvEcc_eccSign(privmxDrvEcc_ECC* ecc, const char* msg, int msglen, privmxDrvEcc_Signature* res) {
    EC_KEY* _ecc = ecc->impl.get();
    ecdsa_sig_unique_ptr ecdsa(ECDSA_do_sign(reinterpret_cast<const unsigned char*>(msg), msglen, _ecc), ECDSA_SIG_free);
    const ECDSA_SIG* raw_sig = ecdsa.get();
    if (raw_sig == NULL) {
        return 1;
    }
    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(raw_sig, &r, &s);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> resr(BN_new(), BN_free);
    if (resr.get() == NULL) {
        return 1;
    }
    if (BN_copy(resr.get(), r) == NULL) {
        return 2;
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> ress(BN_new(), BN_free);
    if (ress.get() == NULL) {
        return 3;
    }
    if (BN_copy(ress.get(), s) == NULL) {
        return 4;
    }
    res->r = new privmxDrvEcc_BN{move(resr)};
    res->s = new privmxDrvEcc_BN{move(ress)};
    return 0;
}

int privmxDrvEcc_eccVerify(privmxDrvEcc_ECC* ecc, const char* msg, int msglen, const privmxDrvEcc_Signature* sig, int* res) {
    EC_KEY* _ecc = ecc->impl.get();
    if (BN_num_bits(sig->r->impl.get()) > 256 || BN_num_bits(sig->s->impl.get()) > 256) {
        return 1;
    }
    ecdsa_sig_unique_ptr ecdsa(ECDSA_SIG_new(), ECDSA_SIG_free);
    ECDSA_SIG* raw_sig = ecdsa.get();
    if (raw_sig == NULL) {
        return 2;
    }
    bignum_unique_ptr r = copyBignum(sig->r->impl.get());
    bignum_unique_ptr s = copyBignum(sig->s->impl.get());
    BIGNUM* raw_r = r.get();
    BIGNUM* raw_s = s.get();
    if (ECDSA_SIG_set0(raw_sig, raw_r, raw_s) == 0) {
        return 3;
    }
    // Release r and s, cause calling ECDSA_SIG_set0() transfers
    // the memory management of the values to the ECDSA_SIG object
    r.release();
    s.release();
    int result = ECDSA_do_verify(reinterpret_cast<const unsigned char*>(msg), msglen, raw_sig, _ecc);
    if (result == -1) {
        return 4;
    }
    *res = (result == 1);
    return 0;
}

int privmxDrvEcc_eccDerive(const privmxDrvEcc_ECC* ecc, const privmxDrvEcc_ECC* pub, char** res, int* reslen) {
    const EC_KEY* _ecc = ecc->impl.get();
    const EC_KEY* _pub = pub->impl.get();
    const EC_GROUP* group = EC_KEY_get0_group(_ecc);
    const EC_POINT* raw_point = EC_KEY_get0_public_key(_pub);
    if (raw_point == NULL) { 
        return 1;
    }
    int field_size = EC_GROUP_get_degree(group);
    size_t secret_len = (field_size + 7) / 8;
    std::string secret(secret_len, 0);
    char* out = secret.data();
    if (ECDH_compute_key(out, secret_len, raw_point, _ecc, NULL) <= 0) {
        return 2;
    }
    char* tmp = (char*)malloc(secret.size());
    memcpy(tmp, secret.data(), secret.size());
    *res = tmp;
    *reslen = secret.size();
    return 0;
}

int privmxDrvEcc_eccGetOrder(privmxDrvEcc_BN** res) {
    ec_group_unique_ptr group = getEcGroup();
    const EC_GROUP* raw_group = group.get();
    const BIGNUM* order = EC_GROUP_get0_order(raw_group);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> _dst(BN_new(), BN_free);
    if (_dst.get() == NULL) {
        return 1;
    }
    if (BN_copy(_dst.get(), order) == NULL) {
        return 2;
    }
    *res = new privmxDrvEcc_BN{move(_dst)};
    return 0;
}

int privmxDrvEcc_eccGetGenerator(privmxDrvEcc_Point** res) {
    ec_group_unique_ptr group = getEcGroup();
    const EC_GROUP* raw_group = group.get();
    const EC_POINT* g = EC_GROUP_get0_generator(raw_group);
    ec_point_unique_ptr new_point = newEcPoint();
    EC_POINT* _dst = new_point.get();
    if (EC_POINT_copy(_dst, g) == 0) {
        return 2;
    }
    *res = new privmxDrvEcc_Point{move(new_point)};
    return 0;
}

int privmxDrvEcc_eccCopy(const privmxDrvEcc_ECC* src, privmxDrvEcc_ECC** dst) {
    ec_key_unique_ptr new_key = newEcKey();
    EC_KEY* _dst = new_key.get();
    const EC_KEY* _src = (const EC_KEY*)src;
    if (EC_KEY_copy(_dst, _src) == NULL) {
        return 1;
    }
    *dst = new privmxDrvEcc_ECC{move(new_key)};
    return 0;
}

int privmxDrvEcc_eccNew(privmxDrvEcc_ECC** res) {
    ec_key_unique_ptr key(EC_KEY_new_by_curve_name(NID_secp256k1), EC_KEY_free);
    if (key.get() == NULL) {
        return 1;
    }
    *res = new privmxDrvEcc_ECC{move(key)};
    return 0;
}

int privmxDrvEcc_eccFree(privmxDrvEcc_ECC* ecc) {
    delete ecc;
    return 0;
}


int privmxDrvEcc_freeMem(void* ptr) {
    free(ptr);
    return 0;
}

