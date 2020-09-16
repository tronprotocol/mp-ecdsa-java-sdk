package org.tron.common.tss;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.junit.Assert;
import org.junit.Test;

public class LibmpecdsaTest {

  @Test
  public void tss2partyTest() {
    int n = 2; //total participants
    int t = 1; //threshold
    Libmpecdsa instance = LibmpecdsaWrapper.getInstance();

    long ctx1 = instance.libmpecdsaKeygenCtxInit(1, n, t);
    // System.out.println("Initialize ctx of party1 " + ctx1);
    long ctx2 = instance.libmpecdsaKeygenCtxInit(2, n, t);
    // System.out.println("Initialize ctx of party2 " + ctx2);

    long signCtx1 = instance.libmpecdsaSignCtxInit(n, t);
    long signCxt2 = instance.libmpecdsaSignCtxInit(n, t);

    boolean testResult = true;
    try {
      // ---------------Round1---------------------------------
      System.out.println("--------------keygen round 1--------------------");
      //party 1
      int[] p1BcLength = new int[1];
      int[] p1DecomLength = new int[1];

      String p1Round1Ans = instance.libmpecdsaKeygenRound1(ctx1, p1BcLength, p1DecomLength);
      // System.out.println("party1 round1Ans: " + p1Round1Ans);
      Assert.assertNotEquals(p1Round1Ans, null);
      Assert.assertTrue(p1Round1Ans.length() == p1DecomLength[0] + p1BcLength[0]);

      //party2
      int[] p2BcLength = new int[1];
      int[] p2DecomLength = new int[1];

      String p2Round1Ans = instance.libmpecdsaKeygenRound1(ctx2, p2BcLength, p2DecomLength);
      // System.out.println("party2 round1Ans: " + p1Round1Ans);
      Assert.assertNotEquals(p2Round1Ans, null);
      Assert.assertTrue(p2Round1Ans.length() == p2DecomLength[0] + p2BcLength[0]);

      //---------------Round2--------------------------------
      System.out.println("--------------keygen round 2--------------------");
      String bcs = p1Round1Ans.substring(0, p1BcLength[0]) + p2Round1Ans.substring(0,
          p2BcLength[0]);
      String decoms = p1Round1Ans.substring(p1BcLength[0]) + p2Round1Ans.substring(p2BcLength[0]);


      int[] bciLength = {p1BcLength[0], p2BcLength[0]};
      int[] decomiLength = {p1DecomLength[0], p2DecomLength[0]};
      //party 1
      int[] p1Round2AnsLen = new int[n - 1];
      String p1Round2Ans = instance.libmpecdsaKeygenRound2(ctx1, bcs, bciLength, decoms,
          decomiLength, p1Round2AnsLen);
      Assert.assertNotEquals(p1Round2Ans, null);
      // System.out.println("party1 round2 ans " + p1Round2Ans);
      Assert.assertTrue(p1Round2Ans.length() == p1Round2AnsLen[0]);

      //party 2
      int[] p2Round2AnsLen = new int[n - 1];
      String p2Round2Ans = instance.libmpecdsaKeygenRound2(ctx2, bcs, bciLength, decoms,
          decomiLength, p2Round2AnsLen);
      Assert.assertNotEquals(p2Round2Ans, null);
      // System.out.println("party2 round2 ans " + p2Round2Ans);
      Assert.assertTrue(p2Round2Ans.length() == p2Round2AnsLen[0]);

      //---------------Round3--------------------------------
      System.out.println("--------------keygen round 3--------------------");
      //party 1
      String p1Round3Ans = instance.libmpecdsaKeygenRound3(ctx1, p2Round2Ans, p2Round2AnsLen);
      Assert.assertNotEquals(p1Round3Ans, null);
      // System.out.println("party1 round3 ans " + p1Round3Ans);

      //party 2
      String p2Round3Ans = instance.libmpecdsaKeygenRound3(ctx2, p1Round2Ans, p1Round2AnsLen);
      Assert.assertNotEquals(p2Round3Ans, null);
      // System.out.println("party2 round3 ans " + p2Round3Ans);

      //---------------Round4--------------------------------
      System.out.println("--------------keygen round 4--------------------");
      //party 1
      int[] p2Round3AnsLen = {p2Round3Ans.length()};
      String p1Round4Ans = instance.libmpecdsaKeygenRound4(ctx1, p2Round3Ans, p2Round3AnsLen);
      Assert.assertNotEquals(p1Round4Ans, null);
      // System.out.println("party1 round4 ans " + p1Round4Ans);
      Assert.assertTrue(p1Round4Ans.length() > 0);

      //party 2
      int[] p1Round3AnsLen = {p1Round3Ans.length()};
      String p2Round4Ans = instance.libmpecdsaKeygenRound4(ctx2, p1Round3Ans, p1Round3AnsLen);
      Assert.assertNotEquals(p1Round4Ans, null);
      // System.out.println("party2 round4 ans " + p2Round4Ans);
      Assert.assertTrue(p2Round4Ans.length() > 0);

      //---------------Round5--------------------------------
      System.out.println("--------------keygen round 5--------------------");
      String dlog_proof = p1Round4Ans + p2Round4Ans;
      int[] dlog_proof_length = {p1Round4Ans.length(), p2Round4Ans.length()};

      //party 1
      String p1Round5Ans = instance.libmpecdsaKeygenRound5(ctx1, dlog_proof, dlog_proof_length);
      Assert.assertNotEquals(p1Round5Ans, null);

      // System.out.println("party1 round5 ans " + p1Round5Ans);
      Assert.assertTrue(p1Round5Ans.length() > 0);

      //party 2
      String p2Round5Ans = instance.libmpecdsaKeygenRound5(ctx2, dlog_proof, dlog_proof_length);
      // System.out.println("party2 round5 ans " + p2Round5Ans);
      Assert.assertNotEquals(p2Round5Ans, null);
      Assert.assertTrue(p2Round5Ans.length() > 0);

      //lastly, party1 encrypt and store p1Round5Ans, and so does party2

      // sign starts here
      //-----------------------sign initialization--------------------
//      System.out.println("Initialize sign ctx of party1 " + signCtx1);
//      System.out.println("Initialize sign ctx of party2 " + signCxt2);

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
      Assert.assertNotEquals(p1SignRound1, null);
      Assert.assertNotEquals(p2SignRound1, null);
      Assert.assertEquals(commit1Length[0] + mA1Length[0], p1SignRound1.length());
      Assert.assertEquals(commit2Length[0] + mA2Length[0], p2SignRound1.length());
//      System.out.println("p1SignRound1" + p1SignRound1);
//      System.out.println("p2SignRound2" + p2SignRound1);
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
      Assert.assertNotEquals(p1SignRound2, null);
      Assert.assertNotEquals(p2SignRound2, null);
      Assert.assertEquals(mBGamma1Length[0] + mBWi1Length[0], p1SignRound2.length());
      Assert.assertEquals(mBGamma2Length[0] + mBWi2Length[0], p2SignRound2.length());
//      System.out.println("p1SignRound2: " + p1SignRound2);
//      System.out.println("p2SignRound2: " + p2SignRound2);

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
      Assert.assertNotEquals(p1SignRound3, null);
      Assert.assertNotEquals(p2SignRound3, null);
//      System.out.println("p1SignRound3: " + p1SignRound3);
//      System.out.println("p2SignRound3: " + p2SignRound3);

      //-----------------------sign round4--------------------
      System.out.println("-----------------------sign round4--------------------");
      String deltaRec = p2SignRound3 + p1SignRound3;
      int [] deltaLength = {p2SignRound3.length(), p1SignRound3.length()};
      String p1SignRound4 = instance.libmpecdsaSignRound4(signCtx1, deltaRec, deltaLength);
      String p2SignRound4 = instance.libmpecdsaSignRound4(signCxt2, deltaRec, deltaLength);
      Assert.assertNotEquals(p1SignRound4, null);
      Assert.assertNotEquals(p2SignRound4, null);
//      System.out.println("p1SignRound4: " + p1SignRound4);
//      System.out.println("p2SignRound4: " + p2SignRound4);

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
      Assert.assertNotEquals(p1SignRound5, null);
      Assert.assertNotEquals(p2SignRound5, null);
//      System.out.println("p1SignRound5: " + p1SignRound5);
//      System.out.println("p2SignRound5: " + p2SignRound5);

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
      Assert.assertNotEquals(p1SignRound6, null);
      Assert.assertNotEquals(p2SignRound6, null);
      Assert.assertEquals(sProofTLength1[0] + sProofTLength1[1] + sProofTLength1[2],
          p1SignRound6.length());
      Assert.assertEquals(sProofTLength2[0] + sProofTLength2[1] + sProofTLength2[2],
          p2SignRound6.length());
//      System.out.println("p1SignRound6: " + p1SignRound6);
//      System.out.println("p2SignRound6: " + p2SignRound6);

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
      byte[] messageHash = new byte[32];
      messageHash[31] = 1;
      String hashStr = bytesToHexString(messageHash);
      String p1SignRound7 = instance
          .libmpecdsaSignRound7(signCtx1, sString, sLength, proofString, proofLength, tString,
              tLength, hashStr);
      String p2SignRound7 = instance
          .libmpecdsaSignRound7(signCxt2, sString, sLength, proofString, proofLength, tString,
              tLength, hashStr);
      Assert.assertNotEquals(p1SignRound7, null);
      Assert.assertNotEquals(p2SignRound7, null);

//      System.out.println("p1SignRound7: " + p1SignRound7);
//      System.out.println("p2SignRound7: " + p2SignRound7);
      //-----------------------sign round7--------------------
      System.out.println("-----------------------sign round8--------------------");
      String sigString = p2SignRound7 + p1SignRound7;
      int[] sigLength = {p2SignRound7.length(), p1SignRound7.length()};

      String p1SignRound8 = instance
          .libmpecdsaSignRound8(signCtx1, sigString, sigLength);
      String p2SignRound8 = instance
          .libmpecdsaSignRound8(signCxt2, sigString, sigLength);
      Assert.assertNotEquals(p1SignRound8, null);
      Assert.assertNotEquals(p2SignRound8, null);
//      System.out.println("p1SignRound8: " + p1SignRound8);
//      System.out.println("p2SignRound8: " + p2SignRound8);
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

  @Test
  public void tssTest() {
    int threshold = 19;
    int totalNum = 27;
    int signerNum = 22;
    int[] signers = new int[signerNum];
    Set<Integer>  set = new HashSet<>();
    while (set.size() < signerNum) {
      int num = (int) (Math.random() * 27);
      set.add(num);
    }
    Iterator<Integer> iter = set.iterator();
    for (int i = 0; i < signerNum; i++) {
      if (iter.hasNext()) {
        signers[i] = iter.next().intValue();
      }
    }
    tssImplTest(threshold, totalNum, signers);
  }

  void tssImplTest(int threshold, int total_number, int[] signers) {
    System.out.println("totalNum: " + total_number + ", threshold: " + threshold);
    Libmpecdsa instance = LibmpecdsaWrapper.getInstance();

    long[] keyCtx = new long[total_number];
    for (int i = 0; i < total_number; i++) {
      keyCtx[i] = instance.libmpecdsaKeygenCtxInit(i + 1, total_number, threshold);
    }
    long[] signCtx = new long[signers.length];
    for (int i = 0; i < signers.length; i++) {
      signCtx[i] = instance.libmpecdsaSignCtxInit(total_number, threshold);
    }

    boolean testResult = true;
    try {
      //---------------Round1---------------------------------
      System.out.println("--------------keygen round 1--------------------");
      int[][] bcLength = new int[total_number][1];
      int[][] decomLength = new int[total_number][1];
      String[] round1Ans = new String[total_number];
      for (int i = 0; i < total_number; i++) {
        round1Ans[i] = instance.libmpecdsaKeygenRound1(keyCtx[i], bcLength[i], decomLength[i]);
        // System.out.println("party " + (i + 1) + " round1Ans: " + round1Ans[i]);
        Assert.assertNotEquals(round1Ans[i], null);
        Assert.assertTrue(round1Ans[i].length() == decomLength[i][0] + bcLength[i][0]);
      }

      //---------------Round2--------------------------------
      System.out.println("--------------keygen round 2--------------------");
      String bcs = new String();
      String decoms = new String();
      for (int i = 0; i < total_number; i++) {
        bcs += round1Ans[i].substring(0, bcLength[i][0]);
        decoms += round1Ans[i].substring(bcLength[i][0]);
      }

      int[] bciLength = new int[total_number];
      int[] decomiLength = new int[total_number];
      for (int i = 0; i < total_number; i++) {
        bciLength[i] = bcLength[i][0];
        decomiLength[i] = decomLength[i][0];
      }

      // for every party
      int[][] round2AnsLen = new int[total_number][total_number - 1];
      String[] round2Ans = new String[total_number];
      for (int i = 0; i < total_number; i++) {
        round2Ans[i] = instance.libmpecdsaKeygenRound2(keyCtx[i], bcs, bciLength, decoms,
            decomiLength, round2AnsLen[i]);
        // System.out.println("party " + (i + 1) + " round2 ans " + round2Ans[i]);
        Assert.assertNotEquals(round2Ans[i], null);
        int sum = 0;
        for (int j = 0; j < total_number - 1; j++) {
          sum += round2AnsLen[i][j];
        }
        Assert.assertTrue(round2Ans[i].length() == sum);
      }

      //round2AnsOrder[i][i] = "";
      //round2AnsOrder[i][j] = {i -> j}
      String[][] round2AnsOrder = new String[total_number][total_number];
      for (int i = 0; i < total_number; i++) {
        int acc = 0;
        for (int j = 0; j < total_number; j++) {
          if (j == i) {
            continue;
          }
          int l = round2AnsLen[i][j < i ? j : j - 1];
          round2AnsOrder[i][j] = round2Ans[i].substring(acc, acc + l);
          acc += l;
        }
      }

      //---------------Round3--------------------------------
      System.out.println("--------------keygen round 3--------------------");
      String[] round3In = new String[total_number];
      int[][] round3InLen = new int[total_number][total_number - 1];
      for (int i = 0; i < total_number; i++) {
        round3In[i] = "";
        for (int j = 0; j < total_number; j++) {
          if (j == i) {
            continue;
          }
          round3In[i] += round2AnsOrder[j][i];
          int index = j < i ? j : j - 1;
          round3InLen[i][index] = round2AnsOrder[j][i].length();
        }
      }

      //for each party
      String[] round3Ans = new String[total_number];
      for (int i = 0; i < total_number; i++) {
        round3Ans[i] = instance.libmpecdsaKeygenRound3(keyCtx[i], round3In[i], round3InLen[i]);
        // System.out.println("party " + (i + 1) + " round3 ans " + round3Ans[i]);
        Assert.assertNotEquals(round3Ans[i], null);
      }

      //---------------Round4--------------------------------
      System.out.println("--------------keygen round 4--------------------");
      //for each party
      int[][] round4InLen = new int[total_number][total_number - 1];
      String[] round4In = new String[total_number];
      for (int i = 0; i < total_number; i++) {
        round4In[i] = "";
        for (int j = 0; j < total_number; j++) {
          if (j == i) {
            continue;
          }
          round4In[i] += round3Ans[j];
          int index = j < i ? j : j - 1;
          round4InLen[i][index] = round3Ans[j].length();
        }
      }

      String[] round4Ans = new String[total_number];
      for (int i = 0; i < total_number; i++) {
        round4Ans[i] = instance.libmpecdsaKeygenRound4(keyCtx[i], round4In[i], round4InLen[i]);
        // System.out.println("party " + (i + 1) + " round4 ans " + round4Ans[i]);
        Assert.assertNotEquals(round4Ans[i], null);
      }

      //---------------Round5--------------------------------
      System.out.println("--------------keygen round 5--------------------");
      String dlog_proof = "";
      int[] dlog_proof_length = new int[total_number];
      for (int i = 0; i < total_number; i++) {
        dlog_proof += round4Ans[i];
        dlog_proof_length[i] = round4Ans[i].length();
      }

      String[] round5Ans = new String[total_number];
      //for each party
      for (int i = 0; i < total_number; i++) {
        round5Ans[i] = instance.libmpecdsaKeygenRound5(keyCtx[i], dlog_proof, dlog_proof_length);
        // System.out.println("party " + (i + 1) + " key length " + round5Ans[i].length());
        Assert.assertNotEquals(round5Ans[i], null);
      }

      //lastly, each party  encrypt and store their result of round5.
      System.out.println("signer number: " + signers.length);
      String s = "[ ";
      for (int i = 0; i < signers.length; i++)
        s = s + signers[i] + " ";
      s = s + "]";
      System.out.println("signers: " + s);

      // sign starts here
      //-----------------------sign round1--------------------
      System.out.println("--------------sign round 1--------------------");
      //signers = {1, 0, 5, 2}
      int signerNum = signers.length;
      int[][] commitLength = new int [signerNum][1];
      int[][] mALength = new int [signerNum][1];
      String[] signRound1 = new String[signerNum];
      for (int i = 0; i < signerNum; i++) {
        signRound1[i] = instance
            .libmpecdsaSignRound1(signCtx[i], round5Ans[signers[i]], signers, signerNum,
                commitLength[i], mALength[i]);
        Assert.assertNotEquals(signRound1[i], null);
        Assert.assertEquals(commitLength[i][0] + mALength[i][0], signRound1[i].length());
      }

      //-----------------------sign round2--------------------
      System.out.println("--------------sign round 2--------------------");
      StringBuffer commitsString = new StringBuffer();
      StringBuffer mAKString = new StringBuffer();
      int[] commitsLength = new int [signerNum];
      int[] mAKLength = new int [signerNum];
      for (int i = 0; i < signerNum; i++) {
        commitsString.append(signRound1[i], 0, commitLength[i][0]);
        mAKString.append(signRound1[i].substring(commitLength[i][0]));
        commitsLength[i] = commitLength[i][0];
        mAKLength[i] = mALength[i][0];
      }
      String[] signRound2 = new String[signerNum];
      int[][] mBGammaLength = new int [signerNum][signerNum - 1];
      int[][] mBWiLength = new int [signerNum][signerNum - 1];
      for(int i = 0; i < signerNum; i++) {
        signRound2[i] = instance
            .libmpecdsaSignRound2(signCtx[i], commitsString.toString(), commitsLength,
                mAKString.toString(), mAKLength, mBGammaLength[i], mBWiLength[i]);
        Assert.assertNotEquals(signRound2[i], null);
        int totalLength = 0;
        for (int j = 0; j < signerNum - 1; j++) {
          totalLength += (mBGammaLength[i][j] + mBWiLength[i][j]);
        }
        Assert.assertEquals(totalLength, signRound2[i].length());
      }

      //-----------------------sign round3--------------------
      System.out.println("--------------sign round 3--------------------");
      String[][] mBGammaSplit = new String[signerNum][signerNum - 1];
      String[][] mBWiSplit = new String[signerNum][signerNum - 1];
      for (int i = 0; i < signerNum; i++) {
        int m = 0;
        for (int j = 0; j < signerNum - 1; j++) {
          mBGammaSplit[i][j] = signRound2[i].substring(m, m + mBGammaLength[i][j]);
          m = m + mBGammaLength[i][j];
        }
        for (int j = 0; j < signerNum -1; j++) {
          mBWiSplit[i][j] = signRound2[i].substring(m, m + mBWiLength[i][j]);
          m = m + mBWiLength[i][j];
        }
      }

      StringBuffer[] mBGammaStr = new StringBuffer[signerNum];
      int[][] mBGammasLength = new int[signerNum][signerNum - 1];
      StringBuffer[] mBWiStr = new StringBuffer[signerNum];
      int[][] mBWisLength = new int[signerNum][signerNum - 1];
      for (int i = 0; i < signerNum; i++) {
        mBGammaStr[i] = new StringBuffer();
        mBWiStr[i] = new StringBuffer();
        if (i == 0) {
          for (int j = 1; j < signerNum; j++) {
            mBGammaStr[i].append(mBGammaSplit[j][i]);
            mBWiStr[i].append(mBWiSplit[j][i]);
            mBGammasLength[i][j - 1] = mBGammaSplit[j][i].length();
            mBWisLength[i][j - 1] = mBWiSplit[j][i].length();
          }
        } else {
          for (int j = 0; j < signerNum; j++) {
            if (j != i) {
              int index = 0;
              int index2 = 0;
              if (j < i) {
                index = i - 1;
                index2 = j;
              } else {
                index = i;
                index2 = j - 1;
              }
              mBGammaStr[i].append(mBGammaSplit[j][index]);
              mBWiStr[i].append(mBWiSplit[j][index]);
              mBGammasLength[i][index2] = mBGammaSplit[j][index].length();
              mBWisLength[i][index2] = mBWiSplit[j][index].length();
            }
          }
        }
      }

      String[] signRound3 = new String[signerNum];
      for (int i = 0; i < signerNum; i++) {
        signRound3[i] = instance
            .libmpecdsaSignRound3(signCtx[i], mBGammaStr[i].toString(), mBGammasLength[i],
                mBWiStr[i].toString(), mBWisLength[i]);
        Assert.assertNotEquals(signRound3[i], null);
      }

      //-----------------------sign round4--------------------
      System.out.println("--------------sign round 4--------------------");
      StringBuffer deltaRec = new StringBuffer();
      int[] deltaLength = new int[signerNum];
      for (int i = 0; i < signerNum; i++) {
        deltaRec.append(signRound3[i]);
        deltaLength[i] = signRound3[i].length();
      }
      String[] signRound4 = new String[signerNum];
      for (int i = 0; i < signerNum; i++) {
        signRound4[i] = instance.libmpecdsaSignRound4(signCtx[i], deltaRec.toString(), deltaLength);
        Assert.assertNotEquals(signRound4[i], null);
      }

      //-----------------------sign round5--------------------
      System.out.println("--------------sign round 5--------------------");
      StringBuffer decommitRec =  new StringBuffer();
      int[] decommitLength = new int[signerNum];
      for (int i = 0; i < signerNum; i++) {
        decommitRec.append(signRound4[i]);
        decommitLength[i] = signRound4[i].length();
      }
      int[][] rDashProofLength = new int[signerNum][3];
      String[] signRound5 = new String[signerNum];
      for (int i = 0; i < signerNum; i++) {
        signRound5[i] = instance
            .libmpecdsaSignRound5(signCtx[i], decommitRec.toString(), decommitLength,
                rDashProofLength[i]);
        Assert.assertNotEquals(signRound5[i], null);
        int length = rDashProofLength[i][0] + rDashProofLength[i][1] +rDashProofLength[i][2];
        Assert.assertEquals(length, signRound5[i].length());
      }

      //-----------------------sign round6--------------------
      System.out.println("--------------sign round 6--------------------");
      StringBuffer rRec = new StringBuffer();
      int[] rLength = new int[signerNum];
      StringBuffer rDashRec = new StringBuffer();
      int[] rDashLength = new int[signerNum];
      StringBuffer phase5ProofRec = new StringBuffer();
      int[] phase5ProofLength = new int[signerNum];
      // all r should be equal
      for (int i = 0; i < signerNum; i++) {
        Assert.assertEquals(signRound5[0].substring(0, rDashProofLength[0][0]), signRound5[i].substring(0, rDashProofLength[i][0]));
      }
      for (int i = 0; i < signerNum; i++) {
        rRec.append(signRound5[i].substring(0, rDashProofLength[i][0]));
        rLength[i] = rDashProofLength[i][0];
        rDashRec.append(signRound5[i]
            .substring(rDashProofLength[i][0], rDashProofLength[i][0] + rDashProofLength[i][1]));
        rDashLength[i] = rDashProofLength[i][1];
        phase5ProofRec.append(signRound5[i].substring(rDashProofLength[i][0] + rDashProofLength[i][1]));
        phase5ProofLength[i] = rDashProofLength[i][2];
      }
      int[][] sProofTLength = new int[signerNum][3];
      String[] signRound6 = new String[signerNum];
      for (int i = 0; i < signerNum; i++) {
        signRound6[i] = instance
            .libmpecdsaSignRound6(signCtx[i], rRec.toString(), rLength, rDashRec.toString(),
                rDashLength, phase5ProofRec.toString(), phase5ProofLength, sProofTLength[i]);
        Assert.assertNotEquals(signRound6[i], null);
        int length = sProofTLength[i][0] + sProofTLength[i][1] + sProofTLength[i][2];
        Assert.assertEquals(length, signRound6[i].length());
      }

      //-----------------------sign round7--------------------
      System.out.println("--------------sign round 7--------------------");
      StringBuffer sString = new StringBuffer();
      int[] sLength = new int[signerNum];
      StringBuffer proofString = new StringBuffer();
      int[] proofLength = new int[signerNum];
      StringBuffer tString = new StringBuffer();
      int[] tLength = new int[signerNum];
      for (int i = 0; i < signerNum; i++) {
        sString.append(signRound6[i].substring(0, sProofTLength[i][0]));
        sLength[i] = sProofTLength[i][0];
        proofString.append(signRound6[i]
            .substring(sProofTLength[i][0], sProofTLength[i][0] + sProofTLength[i][1]));
        proofLength[i] = sProofTLength[i][1];
        tString.append(signRound6[i].substring(sProofTLength[i][0] + sProofTLength[i][1]));
        tLength[i] = sProofTLength[i][2];
      }

      byte[] messageHash = new byte[32];
      messageHash[31] = 1;
      String hashStr = bytesToHexString(messageHash);
      String[] signRound7 = new String[signerNum];
      for (int i = 0; i < signerNum; i++) {
        signRound7[i] = instance
            .libmpecdsaSignRound7(signCtx[i], sString.toString(), sLength, proofString.toString(),
                proofLength, tString.toString(), tLength, hashStr);
        Assert.assertNotEquals(signRound7[i], null);
      }

      //-----------------------sign round8--------------------
      System.out.println("--------------sign round 8--------------------");
      StringBuffer sigString = new StringBuffer();
      int[] sigLength = new int[signerNum];
      for (int i = 0; i < signerNum; i++) {
        sigString.append(signRound7[i]);
        sigLength[i] = signRound7[i].length();
      }
      String[] signRound8 = new String[signerNum];
      for (int i = 0; i < signerNum; i++) {
        signRound8[i] = instance
            .libmpecdsaSignRound8(signCtx[i], sigString.toString(), sigLength);
//        System.out.println(i + " " + signRound8[i]);
        Assert.assertNotEquals(signRound8[i], null);
        Assert.assertEquals(signRound8[0], signRound8[i]);  // all signatures should be equal
      }

    } catch (Throwable e) {
      e.printStackTrace();
      testResult = false;
    } finally {
      for (int i = 0; i < total_number; i++) {
        instance.libmpecdsaKeygenCtxFree(keyCtx[i]);
        // System.out.println("Free keyCtx " + (i + 1) + " successfully.");
      }
      for(int i = 0; i < signers.length; i++) {
        instance.libmpecdsaSignCtxFree(signCtx[i]);
        // System.out.println("Free signCtx " + (i + 1) + " successfully.");
      }
      Assert.assertTrue(testResult);
    }
  }

  String bytesToHexString(byte[] src) {
    StringBuilder stringBuilder = new StringBuilder("");
    if (src == null || src.length <= 0) {
      return null;
    }
    for (int i = 0; i < src.length; i++) {
      int v = src[i] & 0xFF;
      String hv = Integer.toHexString(v);
      if (hv.length() < 2) {
        stringBuilder.append(0);
      }
      stringBuilder.append(hv);
    }
    return stringBuilder.toString();
  }
}
