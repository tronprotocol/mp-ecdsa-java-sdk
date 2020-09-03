package org.tron.common.tss;

import org.junit.Assert;
import org.junit.Test;

public class LibmpecdsaTest {
  public static int N = 2; //total participants
  public static int T = 1; //threshold

  @Test
  public void keygenTest() {
    Libmpecdsa instance = LibmpecdsaWrapper.getInstance();

    long ctx1 = instance.libmpecdsaKeygenCtxInit(1, N, T);
    System.out.println("Initialize ctx of party1 " + ctx1);
    long ctx2 = instance.libmpecdsaKeygenCtxInit(2, N, T);
    System.out.println("Initialize ctx of party2 " + ctx2);

    long signCtx1 = instance.libmpecdsaSignCtxInit(N, T);
    long signCxt2 = instance.libmpecdsaSignCtxInit(N, T);

    boolean testResult = true;
    try {
      //---------------Round1---------------------------------
      System.out.println("--------------round 1--------------------");
      //party 1
      int[] p1BcLength = new int[1];
      int[] p1DecomLength = new int[1];

      String p1Round1Ans = instance.libmpecdsaKeygenRound1(ctx1, p1BcLength, p1DecomLength);
      System.out.println("party1 round1Ans: " + p1Round1Ans);
      Assert.assertTrue(p1Round1Ans.length() == p1DecomLength[0] + p1BcLength[0]);

      //party2
      int[] p2BcLength = new int[1];
      int[] p2DecomLength = new int[1];

      String p2Round1Ans = instance.libmpecdsaKeygenRound1(ctx2, p2BcLength, p2DecomLength);
      System.out.println("party2 round1Ans: " + p1Round1Ans);
      Assert.assertTrue(p2Round1Ans.length() == p2DecomLength[0] + p2BcLength[0]);

      //---------------Round2--------------------------------
      System.out.println("--------------round 2--------------------");
      String bcs = p1Round1Ans.substring(0, p1BcLength[0]) + p2Round1Ans.substring(0,
          p2BcLength[0]);
      String decoms = p1Round1Ans.substring(p1BcLength[0]) + p2Round1Ans.substring(p2BcLength[0]);


      int[] bciLength = {p1BcLength[0], p2BcLength[0]};
      int[] decomiLength = {p1DecomLength[0], p2DecomLength[0]};
      //party 1
      int[] p1Round2AnsLen = new int[N - 1];
      String p1Round2Ans = instance.libmpecdsaKeygenRound2(ctx1, bcs, bciLength, decoms,
          decomiLength, p1Round2AnsLen);
      System.out.println("party1 round2 ans " + p1Round2Ans);
      Assert.assertTrue(p1Round2Ans.length() == p1Round2AnsLen[0]);

      //party 2
      int[] p2Round2AnsLen = new int[N - 1];
      String p2Round2Ans = instance.libmpecdsaKeygenRound2(ctx2, bcs, bciLength, decoms,
          decomiLength, p2Round2AnsLen);
      System.out.println("party2 round2 ans " + p2Round2Ans);
      Assert.assertTrue(p2Round2Ans.length() == p2Round2AnsLen[0]);

      //---------------Round3--------------------------------
      System.out.println("--------------round 3--------------------");
      //party 1
      String p1Round3Ans = instance.libmpecdsaKeygenRound3(ctx1, p2Round2Ans, p2Round2AnsLen);
      System.out.println("party1 round3 ans " + p1Round3Ans);

      //party 2
      String p2Round3Ans = instance.libmpecdsaKeygenRound3(ctx2, p1Round2Ans, p1Round2AnsLen);
      System.out.println("party2 round3 ans " + p2Round3Ans);

      //---------------Round4--------------------------------
      System.out.println("--------------round 4--------------------");
      //party 1
      int[] p2Round3AnsLen = {p2Round3Ans.length()};
      String p1Round4Ans = instance.libmpecdsaKeygenRound4(ctx1, p2Round3Ans, p2Round3AnsLen);
      System.out.println("party1 round4 ans " + p1Round4Ans);
      Assert.assertTrue(p1Round4Ans.length() > 0);

      //party 2
      int[] p1Round3AnsLen = {p1Round3Ans.length()};
      String p2Round4Ans = instance.libmpecdsaKeygenRound4(ctx2, p1Round3Ans, p1Round3AnsLen);
      System.out.println("party2 round4 ans " + p2Round4Ans);
      Assert.assertTrue(p2Round4Ans.length() > 0);

      //---------------Round5--------------------------------
      System.out.println("--------------round 5--------------------");
      String dlog_proof = p1Round4Ans + p2Round4Ans;
      int[] dlog_proof_length = {p1Round4Ans.length(), p2Round4Ans.length()};

      //party 1
      String p1Round5Ans = instance.libmpecdsaKeygenRound5(ctx1, dlog_proof, dlog_proof_length);
      System.out.println("party1 round5 ans " + p1Round5Ans);
      Assert.assertTrue(p1Round5Ans.length() > 0);

      //party 2
      String p2Round5Ans = instance.libmpecdsaKeygenRound5(ctx2, dlog_proof, dlog_proof_length);
      System.out.println("party2 round5 ans " + p2Round5Ans);
      Assert.assertTrue(p2Round5Ans.length() > 0);

      //lastly, party1 encrypt and store p1Round5Ans, and so does party2

      // sign starts here
      //-----------------------sign initialization--------------------
      System.out.println("Initialize sign ctx of party1 " + signCtx1);
      System.out.println("Initialize sign ctx of party2 " + signCxt2);

      //-----------------------sign round1--------------------
      System.out.println("-----------------------sign round1--------------------");
      int[] signers = {1, 0};
      int[] commit1Length = new int[1];
      int[] mA1Length = new int[1];
      String p1SignRound1 = instance
          .libmpecdsaSignRound1(signCtx1, p1Round5Ans, signers, 2, commit1Length, mA1Length);
      int[] commit2Length = new int[1];
      int[] mA2Length = new int[1];
      String p2SignRound1 = instance
          .libmpecdsaSignRound1(signCxt2, p2Round5Ans, signers, 2, commit2Length, mA2Length);

      Assert.assertEquals(commit1Length[0] + mA1Length[0], p1SignRound1.length());
      Assert.assertEquals(commit2Length[0] + mA2Length[0], p2SignRound1.length());
      System.out.println("p1SignRound1" + p1SignRound1);
      System.out.println("p2SignRound2" + p2SignRound1);
      String commitsString =
          p2SignRound1.substring(0, commit2Length[0]) + p1SignRound1.substring(0, commit1Length[0]);
      String mAKString =
          p2SignRound1.substring(commit2Length[0]) + p1SignRound1.substring(commit1Length[0]);

      //-----------------------sign round2--------------------
      System.out.println("-----------------------sign round2--------------------");
      int[] commitsLength = {commit2Length[0], commit1Length[0]};
      int[] mAKLength = {mA2Length[0], mA1Length[0]};
      int[] mBGamma1Length = {0};
      int[] mBWi1Length = {0};
      String p1SignRound2 = instance
          .libmpecdsaSignRound2(signCtx1, commitsString, commitsLength, mAKString, mAKLength,
              mBGamma1Length, mBWi1Length);

      int[] mBGamma2Length = {0};
      int[] mBWi2Length = {0};
      String p2SignRound2 = instance
          .libmpecdsaSignRound2(signCxt2, commitsString, commitsLength, mAKString, mAKLength,
              mBGamma2Length, mBWi2Length);
      Assert.assertEquals(mBGamma1Length[0] + mBWi1Length[0], p1SignRound2.length());
      Assert.assertEquals(mBGamma2Length[0] + mBWi2Length[0], p2SignRound2.length());
      System.out.println("p1SignRound2: " + p1SignRound2);
      System.out.println("p2SignRound2: " + p2SignRound2);

      //-----------------------sign round3--------------------
      System.out.println("-----------------------sign round3--------------------");
      String mBGamma1Str = p2SignRound2.substring(0, mBGamma2Length[0]);
      String mBWi1Str = p2SignRound2.substring(mBGamma2Length[0]);
      String p1SignRound3 = instance
          .libmpecdsaSignRound3(signCtx1, mBGamma1Str, mBGamma2Length, mBWi1Str, mBWi2Length);

      String mBGamma2Str = p1SignRound2.substring(0, mBGamma1Length[0]);
      String mBWi2Str = p1SignRound2.substring(mBGamma1Length[0]);
      String p2SignRound3 = instance
          .libmpecdsaSignRound3(signCxt2, mBGamma2Str, mBGamma1Length, mBWi2Str, mBWi1Length);
      System.out.println("p1SignRound3: " + p1SignRound3);
      System.out.println("p2SignRound3: " + p2SignRound3);

      //-----------------------sign round4--------------------
      System.out.println("-----------------------sign round4--------------------");
      String deltaRec = p2SignRound3 + p1SignRound3;
      int [] deltaLength = {p2SignRound3.length(), p1SignRound3.length()};
      String p1SignRound4 = instance.libmpecdsaSignRound4(signCtx1, deltaRec, deltaLength);
      String p2SignRound4 = instance.libmpecdsaSignRound4(signCxt2, deltaRec, deltaLength);
      System.out.println("p1SignRound4: " + p1SignRound4);
      System.out.println("p2SignRound4: " + p2SignRound4);

      //-----------------------sign round5--------------------
      System.out.println("-----------------------sign round5--------------------");
      String decommitRec = p2SignRound4 + p1SignRound4;
      int[] decommitLength = {p2SignRound4.length(), p1SignRound4.length()};
      int[] rDashProofLength1 = new int[3];
      String p1SignRound5 = instance
          .libmpecdsaSignRound5(signCtx1, decommitRec, decommitLength, rDashProofLength1);
      int[] rDashProofLength2 = new int[3];
      String p2SignRound5 = instance
          .libmpecdsaSignRound5(signCxt2, decommitRec, decommitLength, rDashProofLength2);
      Assert.assertEquals(rDashProofLength1[0] + rDashProofLength1[1] + rDashProofLength1[2],
           p1SignRound5.length());
      Assert.assertEquals(rDashProofLength2[0] + rDashProofLength2[1] + rDashProofLength2[2],
          p2SignRound5.length());
      System.out.println("p1SignRound5: " + p1SignRound5);
      System.out.println("p2SignRound5: " + p2SignRound5);

      //-----------------------sign round6--------------------
      System.out.println("-----------------------sign round6--------------------");
      String rRec = p2SignRound5.substring(0, rDashProofLength2[0]) + p1SignRound5
          .substring(0, rDashProofLength1[0]);
      int[] rLength = {rDashProofLength2[0], rDashProofLength1[0]};
      String rDashRec = p2SignRound5
          .substring(rDashProofLength2[0], rDashProofLength2[0] + rDashProofLength2[1]) +
          p1SignRound5.substring(rDashProofLength1[0], rDashProofLength1[0] + rDashProofLength1[1]);
      int[] rDashLength = {rDashProofLength2[1], rDashProofLength1[1]};
      String phase5ProofRec = p2SignRound5.substring(rDashProofLength2[0] + rDashProofLength2[1]) +
          p1SignRound5.substring(rDashProofLength1[0] + rDashProofLength1[1]);
      int[] phase5ProofLength = {rDashProofLength2[2], rDashProofLength1[2]};

      int[] sProofTLength1 = new int[3];
      String p1SignRound6 = instance
          .libmpecdsaSignRound6(signCtx1, rRec, rLength, rDashRec, rDashLength,
              phase5ProofRec, phase5ProofLength, sProofTLength1);
      int[] sProofTLength2 = new int[3];
      String p2SignRound6 = instance
          .libmpecdsaSignRound6(signCxt2, rRec, rLength, rDashRec, rDashLength,
              phase5ProofRec, phase5ProofLength, sProofTLength2);
      Assert.assertEquals(sProofTLength1[0] + sProofTLength1[1] + sProofTLength1[2],
           p1SignRound6.length());
      Assert.assertEquals(sProofTLength2[0] + sProofTLength2[1] + sProofTLength2[2],
          p2SignRound6.length());
      System.out.println("p1SignRound6: " + p1SignRound6);
      System.out.println("p2SignRound6: " + p2SignRound6);

      //-----------------------sign round7--------------------
      System.out.println("-----------------------sign round7--------------------");
      String sString = p2SignRound6.substring(0, sProofTLength2[0]) +
          p1SignRound6.substring(0, sProofTLength1[0]);
      int[] sLength = {sProofTLength2[0], sProofTLength1[0]};
      String proofString = p2SignRound6
          .substring(sProofTLength2[0], sProofTLength2[0] + sProofTLength2[1]) +
          p1SignRound6.substring(sProofTLength1[0], sProofTLength1[0] + sProofTLength1[1]);
      int[] proofLength = {sProofTLength2[1], sProofTLength1[1]};
      String tString = p2SignRound6.substring(sProofTLength2[0] + sProofTLength2[1]) +
          p1SignRound6.substring(sProofTLength1[0] + sProofTLength1[1]);
      int[] tLength = {sProofTLength2[2], sProofTLength1[2]};
      String message = "multi-party ecdsa signature";

      int[] sigSiLength1 = new int[2];
      String p1SignRound7 = instance
          .libmpecdsaSignRound7(signCtx1, sString, sLength, proofString, proofLength, tString,
              tLength, message, sigSiLength1);
      int[] sigSiLength2 = new int[2];
      String p2SignRound7 = instance
          .libmpecdsaSignRound7(signCxt2, sString, sLength, proofString, proofLength, tString,
              tLength, message, sigSiLength2);

      Assert.assertEquals(sigSiLength1[0] + sigSiLength1[1], p1SignRound7.length());
      Assert.assertEquals(sigSiLength2[0] + sigSiLength2[1], p2SignRound7.length());
      System.out.println("p1SignRound7: " + p1SignRound7);
      System.out.println("p2SignRound7: " + p2SignRound7);
      //-----------------------sign round7--------------------
      System.out.println("-----------------------sign round8--------------------");
      String sigString = p2SignRound7.substring(0, sigSiLength2[0]) +
          p1SignRound7.substring(0, sigSiLength1[0]);
      int[] sigLength = {sigSiLength2[0], sigSiLength1[0]};
      String siString =
          p2SignRound7.substring(sigSiLength2[0]) + p1SignRound7.substring(sigSiLength2[0]);
      int[] siLength = {sigSiLength2[1], sigSiLength1[1]};

      String p1SignRound8 = instance
          .libmpecdsaSignRound8(signCtx1, sigString, sigLength, siString, siLength);
      String p2SignRound8 = instance
          .libmpecdsaSignRound8(signCxt2, sigString, sigLength, siString, siLength);

      System.out.println("p1SignRound8: " + p1SignRound8);
      System.out.println("p2SignRound8: " + p2SignRound8);
      Assert.assertEquals(p1SignRound8, p2SignRound8);


    } catch (Throwable e) {
      e.printStackTrace();
      testResult = false;
    } finally {
      instance.libmpecdsaKeygenCtxFree(ctx1);
      instance.libmpecdsaKeygenCtxFree(ctx2);

      instance.libmpecdsaSignCtxFree(signCtx1);
      instance.libmpecdsaSignCtxFree(signCxt2);
      System.out.println("Free ctx successfully.");
      Assert.assertTrue(testResult);
    }
  }
}
