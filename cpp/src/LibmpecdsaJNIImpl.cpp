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
//            const char *ciphertexts,//exclude self
//            const int32_t *ciphertext_i_length, //size = party_total - 1
//    );

    const char *c = (const char*) env->GetStringUTFChars(ciphertexts, nullptr);
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
 * Signature: (JLjava/lang/String;[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
        Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenRound4
        (JNIEnv * env, jobject, jlong ctx, jstring vss_schemes, jintArray vss_scheme_length) {
//    char *libmpecdsa_keygen_round4(
//            void *ctx,
//            const char *vss_schemes, //exclude self
//            const int32_t *vss_scheme_length //size = party_total - 1
//    );

    const char *v = (const char*) env->GetStringUTFChars(vss_schemes, nullptr);
    const jint *vl = env->GetIntArrayElements(vss_scheme_length, nullptr);

    if (v == NULL || vl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_keygen_round4((void *)ctx, v, vl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(vss_schemes, v);
    env->ReleaseIntArrayElements(vss_scheme_length, (jint *)vl, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaKeygenRound5
 * Signature: (JLjava/lang/String;[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
        Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaKeygenRound5
        (JNIEnv * env, jobject, jlong ctx, jstring dlog_proofs, jintArray dlof_proof_length) {
//    char *libmpecdsa_keygen_round5(
//            void *ctx,
//            const char *dlog_proofs, // self included
//            const int32_t *dlof_proof_length // size = party_total
//    );

    const char *d = (const char*) env->GetStringUTFChars(dlog_proofs, nullptr);
    const jint *dl = env->GetIntArrayElements(dlof_proof_length, nullptr);

    if (d == NULL || dl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_keygen_round5((void *)ctx, d, dl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(dlog_proofs, d);
    env->ReleaseIntArrayElements(dlof_proof_length, (jint *)dl, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignCtxInit
 * Signature: (II)J
 */
JNIEXPORT jlong JNICALL
Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignCtxInit
    (JNIEnv * env, jobject, jint n, jint t) {
//    void *libmpecdsa_sign_ctx_init(
//            int32_t party_total,  // n
//            int32_t threshold    //  t
//    );

    return (jlong) libmpecdsa_sign_ctx_init((size_t) n, (size_t) t);
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignCtxFree
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignCtxFree
    (JNIEnv * env, jobject, jlong ctx) {
//    void *libmpecdsa_sign_ctx_free(void *);
    libmpecdsa_sign_ctx_free((void *) ctx);
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound1
 * Signature: (JLjava/lang/String;[II[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound1
    (JNIEnv * env, jobject, jlong ctx, jstring keygen_result, jintArray signers, jint signers_num,
    jintArray commit_length, jintArray m_a_k_length) {
//char *libmpecdsa_sign_round1(
//        void *ctx,
//        const char *keygen_result,      //the keygen result
//        const int32_t *signers,         //the parties envolving in generating the signature
//        int32_t signers_num,      //the number of signers, must be larger that threshold (t)
//        int32_t *commit_length,   // the length of commit in the returned value, size = 1
//        int32_t *m_a_k_length       // the length of m_a_k in the returned value, size = 1
//);
    const char *k = (const char*) env->GetStringUTFChars(keygen_result, nullptr);
    const jint *s = env->GetIntArrayElements(signers, nullptr);

    jint *c = env->GetIntArrayElements(commit_length, nullptr);
    jint *m = env->GetIntArrayElements(m_a_k_length, nullptr);

    if (k == NULL || s == NULL || c == NULL || m == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round1((void *)ctx, k, s, (size_t) signers_num, c, m);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(keygen_result, k);
    env->ReleaseIntArrayElements(signers, (jint *)s, 0);
    env->ReleaseIntArrayElements(commit_length, c, 0);
    env->ReleaseIntArrayElements(m_a_k_length, m, 0);

    return result;
}


/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound2
 * Signature: (JLjava/lang/String;[ILjava/lang/String;[I[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound2
    (JNIEnv * env, jobject, jlong ctx, jstring commits, jintArray commits_length, jstring m_a_ks,
    jintArray m_a_ks_length, jintArray m_b_gamma_length, jintArray m_b_wi_length) {
//char *libmpecdsa_sign_round2(
//        void *ctx,
//        const char *commits,                //size = signers_num
//        const int32_t *commits_length,      // size = signers_num
//        const char *m_a_ks,                 // size = signers_num
//        const int32_t *m_a_ks_length,       // size = signers_num
//        int32_t *m_b_gamma_length,    // size = signers_num - 1
//        int32_t *m_b_wi_length        // size = signers_num - 1
//);
    const char *c = (const char*) env->GetStringUTFChars(commits, nullptr);
    const jint *cl = env->GetIntArrayElements(commits_length, nullptr);
    const char *m = (const char*) env->GetStringUTFChars(m_a_ks, nullptr);
    const jint *ml = env->GetIntArrayElements(m_a_ks_length, nullptr);

    jint *mb = env->GetIntArrayElements(m_b_gamma_length, nullptr);
    jint *mw = env->GetIntArrayElements(m_b_wi_length, nullptr);

    if (c == NULL || cl == NULL || m == NULL || ml == NULL || mb == NULL || mw == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round2((void *)ctx, c, cl, m, ml, mb, mw);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(commits, c);
    env->ReleaseIntArrayElements(commits_length, (jint *)cl, 0);
    env->ReleaseStringUTFChars(m_a_ks, m);
    env->ReleaseIntArrayElements(m_a_ks_length, (jint*)ml, 0);
    env->ReleaseIntArrayElements(m_b_gamma_length, mb, 0);
    env->ReleaseIntArrayElements(m_b_wi_length, mw, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound3
 * Signature: (JLjava/lang/String;[ILjava/lang/String;[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound3
    (JNIEnv * env, jobject, jlong ctx, jstring m_b_gamma_rec, jintArray m_b_gamma_length,
    jstring m_b_wi_rec, jintArray m_b_wi_length) {
//char *libmpecdsa_sign_round3(
//       void *ctx,
//       const char *m_b_gamma_rec,         // size = signers_num - 1
//       const int32_t *m_b_gamma_length,   // size = signers_num - 1
//       const char *m_b_wi_rec,            // size = signers_num - 1
//       const int32_t *m_b_wi_rec_length   // size = signers_num - 1
//);
    const char *mg = (const char*) env->GetStringUTFChars(m_b_gamma_rec, nullptr);
    const jint *mgl = env->GetIntArrayElements(m_b_gamma_length, nullptr);
    const char *mw = (const char*) env->GetStringUTFChars(m_b_wi_rec, nullptr);
    const jint *mwl = env->GetIntArrayElements(m_b_wi_length, nullptr);

    if (mg == NULL || mgl == NULL || mw == NULL || mwl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round3((void *)ctx, mg, mgl, mw, mwl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(m_b_wi_rec, mg);
    env->ReleaseIntArrayElements(m_b_gamma_length, (jint *)mgl, 0);
    env->ReleaseStringUTFChars(m_b_wi_rec, mw);
    env->ReleaseIntArrayElements(m_b_wi_length, (jint *)mwl, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound4
 * Signature: (JLjava/lang/String;[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound4
    (JNIEnv * env, jobject, jlong ctx, jstring delta_i_rec, jintArray delta_i_length) {
//char *libmpecdsa_sign_round4(
//       void *ctx,
//       const char *delta_i_rec,    // size = signers_num
//       const int32_t *delta_i_length   // size = signers_nun
//);
    const char *d = (const char*) env->GetStringUTFChars(delta_i_rec, nullptr);
    const jint *dl = env->GetIntArrayElements(delta_i_length, nullptr);

    if (d == NULL || dl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round4((void *)ctx, d, dl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(delta_i_rec, d);
    env->ReleaseIntArrayElements(delta_i_length, (jint *)dl, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound5
 * Signature: (JLjava/lang/String;[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound5
    (JNIEnv * env, jobject, jlong ctx, jstring decommit_rec, jintArray decommit_length,
      jintArray r_dash_proof_length) {
//char *libmpecdsa_sign_round5(
//       void *ctx,
//       const char *decommit_rec,         // size = signers_num
//       const int32_t *decommit_length,     // size = signers_num
//       int32_t *r_dash_proof_length   // size = 3
//);
    const char *d = (const char*) env->GetStringUTFChars(decommit_rec, nullptr);
    const jint *dl = env->GetIntArrayElements(decommit_length, nullptr);
    jint *rl = env->GetIntArrayElements(r_dash_proof_length, nullptr);

    if (d == NULL || dl == NULL || rl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round5((void *)ctx, d, dl, rl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(decommit_rec, d);
    env->ReleaseIntArrayElements(decommit_length, (jint *)dl, 0);
    env->ReleaseIntArrayElements(r_dash_proof_length, rl, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound6
 * Signature: (JLjava/lang/String;[ILjava/lang/String;[ILjava/lang/String;[I[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound6
    (JNIEnv * env, jobject, jlong ctx, jstring R_rec, jintArray R_length, jstring R_dash_rec,
      jintArray R_dash_length, jstring phase5_proof_rec, jintArray phase5_proof_length,
      jintArray S_proof_T_length) {
//char *libmpecdsa_sign_round6(
//       void *ctx,
//       const char *R_rec,           // size = signers_num
//       const int32_t *R_length,     // size = signers_num
//       const char *R_dash_rec,        // size = signers_num
//       const int32_t *R_dash_length,       // size = signers_num
//       const char *phase5_proof_rec,       // size = signers_num
//       const int32_t *phase5_proof_length,  // size = signers_num
//       int32_t *S_proof_T_length     // size =  3
//);
    const char *rr = (const char*) env->GetStringUTFChars(R_rec, nullptr);
    const jint *rrl = env->GetIntArrayElements(R_length, nullptr);
    const char *rd = (const char*) env->GetStringUTFChars(R_dash_rec, nullptr);
    const jint *rdl = env->GetIntArrayElements(R_dash_length, nullptr);
    const char *p = (const char*) env->GetStringUTFChars(phase5_proof_rec, nullptr);
    const jint *pl = env->GetIntArrayElements(phase5_proof_length, nullptr);
    jint *s = env->GetIntArrayElements(S_proof_T_length, nullptr);

    if (rr == NULL || rrl == NULL || rd == NULL || rdl == NULL ||
        p == NULL || pl == NULL || s == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round6((void *)ctx, rr, rrl, rd, rdl, p, pl, s);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(R_rec, rr);
    env->ReleaseIntArrayElements(R_length, (jint *)rrl, 0);
    env->ReleaseStringUTFChars(R_dash_rec, rd);
    env->ReleaseIntArrayElements(R_dash_length, (jint *)rdl, 0);
    env->ReleaseStringUTFChars(phase5_proof_rec, p);
    env->ReleaseIntArrayElements(phase5_proof_length, (jint *)pl, 0);
    env->ReleaseIntArrayElements(S_proof_T_length, s, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound7
 * Signature: (JLjava/lang/String;[ILjava/lang/String;[ILjava/lang/String;[ILjava/lang/String;[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound7
    (JNIEnv * env, jobject, jlong ctx, jstring S_rec, jintArray S_length, jstring homo_proof_rec,
     jintArray homo_proof_length, jstring T_i_rec, jintArray T_i_length, jstring message_hash,
     jintArray sig_s_i_length) {
//char *libmpecdsa_sign_round7(
//       void *ctx,
//       const char *S_rec,           // size = signers_num
//       const int32_t *S_length,          // size = singers_num
//       const char *homo_proof_rec,          //size = signers_num
//       const int32_t *homo_proof_length,    //size = signers_num
//       const char *T_i_rec,                 // size = signers_num
//       const int32_t *T_i_length,          // size = signers_num
//       const char *message               // the 32 bytes message hash to be signed
//       int32_t *sig_s_i_length,      // size = 2

//);
    const char *s = (const char*) env->GetStringUTFChars(S_rec, nullptr);
    const jint *sl = env->GetIntArrayElements(S_length, nullptr);
    const char *h = (const char*) env->GetStringUTFChars(homo_proof_rec, nullptr);
    const jint *hl = env->GetIntArrayElements(homo_proof_length, nullptr);
    const char *t = (const char*) env->GetStringUTFChars(T_i_rec, nullptr);
    const jint *tl = env->GetIntArrayElements(T_i_length, nullptr);
    const char *m = (const char*) env->GetStringUTFChars(message_hash, nullptr);
    jint *ss = env->GetIntArrayElements(sig_s_i_length, nullptr);

    if (s == NULL || sl == NULL || h == NULL || hl == NULL ||
        t == NULL || tl == NULL || m == NULL || ss == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round7((void *)ctx, s, sl, h, hl, t, tl, m, ss);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(S_rec, s);
    env->ReleaseIntArrayElements(S_length, (jint *)sl, 0);
    env->ReleaseStringUTFChars(homo_proof_rec, h);
    env->ReleaseIntArrayElements(homo_proof_length, (jint *)hl, 0);
    env->ReleaseStringUTFChars(T_i_rec, t);
    env->ReleaseIntArrayElements(T_i_length, (jint *)tl, 0);
    env->ReleaseStringUTFChars(message_hash, m);
    env->ReleaseIntArrayElements(sig_s_i_length, ss, 0);

    return result;
}

/*
 * Class:     org_tron_common_tss_Libmpecdsa_LibmpecdsaJNI
 * Method:    libmpecdsaSignRound8
 * Signature: (JLjava/lang/String;[ILjava/lang/String;[I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_tron_common_tss_Libmpecdsa_00024LibmpecdsaJNI_libmpecdsaSignRound8
    (JNIEnv * env, jobject, jlong ctx, jstring local_sig_rec, jintArray local_sig_length,
    jstring s_i_rec, jintArray s_i_length) {
//char *libmpecdsa_sign_round8(
//      void *ctx,
//      const char *local_sig_rec,           // size = signers_num
//      const int32_t *local_sig_length,     // size = signers_num
//      const char *s_i_rec,                 //  size = signers_num
//      const int32_t *s_i_length            // size = signers_num
//);
    const char *l = (const char*) env->GetStringUTFChars(local_sig_rec, nullptr);
    const jint *ll = env->GetIntArrayElements(local_sig_length, nullptr);
    const char *s = (const char*) env->GetStringUTFChars(s_i_rec, nullptr);
    const jint *sl = env->GetIntArrayElements(s_i_length, nullptr);

    if (l == NULL || ll == NULL || s == NULL || sl == NULL) {
        return NULL;
    }

    char *r = libmpecdsa_sign_round8((void *)ctx, l, ll, s, sl);
    jstring result = env->NewStringUTF(r);

    env->ReleaseStringUTFChars(local_sig_rec, l);
    env->ReleaseIntArrayElements(local_sig_length, (jint *)ll, 0);
    env->ReleaseStringUTFChars(s_i_rec, s);
    env->ReleaseIntArrayElements(s_i_length, (jint *)sl, 0);

    return result;
}
