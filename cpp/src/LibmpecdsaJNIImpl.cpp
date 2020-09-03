#include "org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI.h"
#include "libmpecdsa.h"
#include <iostream>

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenCtxInit
 * Signature: (III)J
 */
JNIEXPORT jlong JNICALL
Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenCtxInit
    (JNIEnv * env, jobject, jint i, jint n, jint t) {
//    void *libmpecdsa_kengen_ctx_init(
//            int32_t party_index, // >= 1
//            int32_t party_total, // n
//            int32_t threshold // t
//    );
    return (jlong) libmpecdsa_keygen_ctx_init((size_t) i, (size_t) n, (size_t) t);
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenCtxFree
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenCtxFree
    (JNIEnv * env, jobject, jlong ctx) {
//    void *libmpecdsa_keygen_ctx_free(void *);
    libmpecdsa_keygen_ctx_free((void *) ctx);
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenRound1
 * Signature: (J[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenRound1
    (JNIEnv * env, jobject, jlong ctx, jintArray bc_length, jintArray decom_length) {
//char *libmpecdsa_keygen_round1(
//        void *ctx,
//        int32_t *bc_length, // size = 1
//        int32_t *decom_length // size = 1
//);
    jint *b = env->GetIntArrayElements(bc_length, nullptr);
    jint *d = env->GetIntArrayElements(decom_length, nullptr);

    if (b == NULL || d == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_keygen_round1((void *)ctx, b, d);
    jstring result = env->NewStringUTF(r);

    env->ReleaseIntArrayElements(bc_length, b, 0);
    env->ReleaseIntArrayElements(decom_length, d, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenRound2
 * Signature: (JLjava/lang/String;[ILjava/lang/String;[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
        Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenRound2
        (JNIEnv * env, jobject, jlong ctx, jstring bcs, jintArray bc_i_length, jstring decoms,
        jintArray decom_i_length, jintArray ciphertexts_length) {
//char *libmpecdsa_keygen_round2(
//        void *ctx,
//        const char *bcs, // self included
//        const int32_t *bc_i_length, // size = part_total
//        const char *decoms, // self included
//        const int32_t *decom_i_length, // size = party_total
//        int32_t *ciphertexts_length // size = party_total - 1
//);

    const char *b = (const char*) env->GetStringUTFChars(bcs, nullptr);
    const jint *bl = env->GetIntArrayElements(bc_i_length, nullptr);
    const char *d = (const char*) env->GetStringUTFChars(decoms, nullptr);
    const jint *dl = env->GetIntArrayElements(decom_i_length, nullptr);
    jint *cl =  env->GetIntArrayElements(ciphertexts_length, nullptr);

    if (b == NULL || bl == NULL || d == NULL || dl == NULL || cl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_keygen_round2((void *)ctx, b, bl, d, dl, cl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(bcs, b);
    env->ReleaseIntArrayElements(bc_i_length, (jint *)bl, 0);
    env->ReleaseStringUTFChars(decoms, d);
    env->ReleaseIntArrayElements(decom_i_length, (jint *)dl, 0);
    env->ReleaseIntArrayElements(ciphertexts_length, cl, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenRound3
 * Signature: (JLjava/lang/String;[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
        Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenRound3
        (JNIEnv * env, jobject, jlong ctx, jstring ciphertexts, jintArray ciphertext_i_length) {
//    char *libmpecdsa_keygen_round3(
//            void *ctx,
//            char *ciphertexts,//exclude self
//            const int32_t *ciphertext_i_length, //size = party_total - 1
//    );

    char *c = (char*) env->GetStringUTFChars(ciphertexts, nullptr);
    const jint *cil = env->GetIntArrayElements(ciphertext_i_length, nullptr);

    if (c == NULL || cil == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_keygen_round3((void *)ctx, c, cil);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(ciphertexts, c);
    env->ReleaseIntArrayElements(ciphertext_i_length, (jint *)cil, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenRound4
 * Signature: (JLjava/lang/String;[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
        Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenRound4
        (JNIEnv * env, jobject, jlong ctx, jstring vss_schemes, jintArray vss_scheme_length,
        jintArray result_length) {
//    char *libmpecdsa_keygen_round4(
//            void *ctx,
//            char *vss_schemes, //exclude self
//            const int32_t *vss_scheme_length, //size = party_total - 1
//            int32_t *result_length //size = 1
//    );

    char *v = (char*) env->GetStringUTFChars(vss_schemes, nullptr);
    const jint *vl = env->GetIntArrayElements(vss_scheme_length, nullptr);
    jint *rl = env->GetIntArrayElements(result_length, nullptr);

    if (v == NULL || vl == NULL || rl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_keygen_round4((void *)ctx, v, vl, rl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(vss_schemes, v);
    env->ReleaseIntArrayElements(vss_scheme_length, (jint *)vl, 0);
    env->ReleaseIntArrayElements(result_length, rl, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenRound5
 * Signature: (JLjava/lang/String;[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
        Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenRound5
        (JNIEnv * env, jobject, jlong ctx, jstring dlog_proofs, jintArray dlof_proof_length,
        jintArray result_length) {
//    char *libmpecdsa_keygen_round5(
//            void *ctx,
//            char *dlog_proofs, // self included
//            const int32_t *dlof_proof_length, // size = party_total
//            int32_t *result_length //size = 1
//    );

    char *d = (char*) env->GetStringUTFChars(dlog_proofs, nullptr);
    const jint *dl = env->GetIntArrayElements(dlof_proof_length, nullptr);
    jint *rl = env->GetIntArrayElements(result_length, nullptr);

    if (d == NULL || dl == NULL || rl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_keygen_round5((void *)ctx, d, dl, rl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(dlog_proofs, d);
    env->ReleaseIntArrayElements(dlof_proof_length, (jint *)dl, 0);
    env->ReleaseIntArrayElements(result_length, rl, 0);

    return result;
}
