package org.tron.common.tss;

class Libmpecdsa {
  private static final LibmpecdsaJNI INSTANCE = new LibmpecdsaJNI();

  public long libmpecdsaKeygenCtxInit(int i, int n, int t) {
    return INSTANCE.libmpecdsaKeygenCtxInit(i, n, t);
  }

  public void libmpecdsaKeygenCtxFree(long ctx) {
    INSTANCE.libmpecdsaKeygenCtxFree(ctx);
  }

  public String libmpecdsaKeygenRound1(long ctx, int[] bcLength, int[] decomLength) {
    return INSTANCE.libmpecdsaKeygenRound1(ctx, bcLength, decomLength);
  }

  public String libmpecdsaKeygenRound2(long ctx, String bcs, int[] bciLength, String decoms,
      int[] decomiLength, int[] ciphertextsLength) {
    return INSTANCE.libmpecdsaKeygenRound2(ctx, bcs, bciLength, decoms, decomiLength,
        ciphertextsLength);
  }

  public String libmpecdsaKeygenRound3(long ctx, String ciphertexts, int[] ciphertextiLength) {
    return INSTANCE.libmpecdsaKeygenRound3(ctx, ciphertexts, ciphertextiLength);
  }

  public String libmpecdsaKeygenRound4(long ctx, String vssSchemes, int[] vssSchemeLength) {
    return INSTANCE.libmpecdsaKeygenRound4(ctx, vssSchemes, vssSchemeLength);
  }

  public String libmpecdsaKeygenRound5(long ctx, String dlogProofs, int[] dlofProofLength) {
    return INSTANCE.libmpecdsaKeygenRound5(ctx, dlogProofs, dlofProofLength);
  }

  public long libmpecdsaSignCtxInit(int n, int t) {
    return INSTANCE.libmpecdsaSignCtxInit(n, t);
  }

  public void libmpecdsaSignCtxFree(long ctx) {
    INSTANCE.libmpecdsaSignCtxFree(ctx);
  }

  public String libmpecdsaSignRound1(long ctx, String keygenResult, int[] signers,
      int signersNum, int[] commitLength, int[] mAKLength) {
    return INSTANCE
        .libmpecdsaSignRound1(ctx, keygenResult, signers, signersNum, commitLength, mAKLength);
  }

  public String libmpecdsaSignRound2(long ctx, String commits, int[] commitsLength,
      String mAKs, int[] mAKsLength, int[] mBGammaLength, int[] mBWiLength) {
    return INSTANCE
        .libmpecdsaSignRound2(ctx, commits, commitsLength, mAKs, mAKsLength, mBGammaLength,
            mBWiLength);
  }

  public String libmpecdsaSignRound3(long ctx, String mBGammaRec, int[] mBGammaLength,
      String mBWiRec, int[] mBWiRecLengh) {
    return INSTANCE.libmpecdsaSignRound3(ctx, mBGammaRec, mBGammaLength, mBWiRec, mBWiRecLengh);
  }

  public String libmpecdsaSignRound4(long ctx, String deltaIRec, int[] deltaILength) {
    return INSTANCE.libmpecdsaSignRound4(ctx, deltaIRec, deltaILength);
  }

  public String libmpecdsaSignRound5(long ctx, String decommitRec, int[] decommitLength,
      int[] rDashProofLength) {
    return INSTANCE.libmpecdsaSignRound5(ctx, decommitRec, decommitLength, rDashProofLength);
  }

  public String libmpecdsaSignRound6(long ctx, String rRec, int[] rLength,
      String rDash, int[] rDashLength, String phase5ProofRec, int[] phase5ProofLength,
      int[] sProofTLength) {
    return INSTANCE.libmpecdsaSignRound6(ctx, rRec, rLength, rDash, rDashLength, phase5ProofRec,
        phase5ProofLength, sProofTLength);
  }

  public String libmpecdsaSignRound7(long ctx, String sRec, int[] sLength,
      String homoProofRec, int[] homoProofLength, String tiRec, int[] tiLength,
      String messageHash, int[] sigSiLength) {
    return INSTANCE
        .libmpecdsaSignRound7(ctx, sRec, sLength, homoProofRec, homoProofLength, tiRec, tiLength,
            messageHash, sigSiLength);
  }

  public String libmpecdsaSignRound8(long ctx, String localSigRec, int[] localSigLength,
      String siRec, int[] siLength) {
    return INSTANCE.libmpecdsaSignRound8(ctx, localSigRec, localSigLength, siRec, siLength);
  }


  private static class LibmpecdsaJNI {

    private native long libmpecdsaKeygenCtxInit(int i, int n, int t);

    private native void libmpecdsaKeygenCtxFree(long ctx);

    private native String libmpecdsaKeygenRound1(long ctx, int[] bcLength, int[] decomLength);

    private native String libmpecdsaKeygenRound2(long ctx, String bcs, int[] bciLength,
        String decoms, int[] decomiLength, int[] ciphertextsLength);

    private native String libmpecdsaKeygenRound3(long ctx, String ciphertexts,
        int[] ciphertextiLength);

    private native String libmpecdsaKeygenRound4(long ctx, String vssSchemes,
        int[] vssSchemeLength);

    private native String libmpecdsaKeygenRound5(long ctx, String dlogProofs,
        int[] dlofProofLength);

    private native long libmpecdsaSignCtxInit(int n, int t);

    private native void libmpecdsaSignCtxFree(long ctx);

    private native String libmpecdsaSignRound1(long ctx, String keygenResult, int[] signers,
         int signersNum, int[] commitLength, int[] mAKLength);

    private native String libmpecdsaSignRound2(long ctx, String commits, int[] commitsLength,
         String mAKs, int[] mAKsLength, int[] mBGammaLength, int[] mBWiLength);

    private native String libmpecdsaSignRound3(long ctx, String mBGammaRec, int[] mBGammaLength,
         String mBWiRec, int[] mBWiRecLengh);

    private native String libmpecdsaSignRound4(long ctx, String deltaIRec, int[] deltaILength);

    private native String libmpecdsaSignRound5(long ctx, String decommitRec, int[] decommitLength,
         int[] rDashProofLength);

    private native String libmpecdsaSignRound6(long ctx, String rRec, int[] rLength,
        String rDash, int[] rDashLength, String phase5ProofRec, int[] phase5ProofLength,
        int[] sProofTLength);

    private native String libmpecdsaSignRound7(long ctx, String sRec, int[] sLength,
        String homoProofRec, int[] homoProofLength, String tiRec, int[] tiLength,
        String messageHash, int[] sigSiLength);

    private native String libmpecdsaSignRound8(long ctx, String localSigRec, int[] localSigLength,
        String siRec, int[] siLength);

  }
}

