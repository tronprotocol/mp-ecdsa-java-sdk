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

  public String libmpecdsaKeygenRound4(long ctx, String vssSchemes, int[] vssSchemeLength,
      int[] resultLength) {
    return INSTANCE.libmpecdsaKeygenRound4(ctx, vssSchemes, vssSchemeLength, resultLength);
  }

  public String libmpecdsaKeygenRound5(long ctx, String dlogProofs, int[] dlofProofLength,
      int[] resultLength) {
    return INSTANCE.libmpecdsaKeygenRound5(ctx, dlogProofs, dlofProofLength, resultLength);
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
        int[] vssSchemeLength, int[] resultLength);

    private native String libmpecdsaKeygenRound5(long ctx, String dlogProofs,
        int[] dlofProofLength, int[] resultLength);

  }
}

