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
    System.out.println("Initialize ctx of party1 " + ctx2);

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
      int[] p1Round4AnsLen = new int[N -1];
      int[] p2Round3AnsLen = {p2Round3Ans.length()};
      String p1Round4Ans = instance.libmpecdsaKeygenRound4(ctx1, p2Round3Ans, p2Round3AnsLen,
          p1Round4AnsLen);
      System.out.println("party1 round4 ans " + p1Round4Ans);
      Assert.assertTrue(p1Round4Ans.length() == p1Round4AnsLen[0]);

      //party 2
      int[] p2Round4AnsLen = new int[N -1];
      int[] p1Round3AnsLen = {p1Round3Ans.length()};
      String p2Round4Ans = instance.libmpecdsaKeygenRound4(ctx2, p1Round3Ans, p1Round3AnsLen,
          p2Round4AnsLen);
      System.out.println("party2 round4 ans " + p2Round4Ans);
      Assert.assertTrue(p2Round4Ans.length() == p2Round4AnsLen[0]);

      //---------------Round5--------------------------------
      System.out.println("--------------round 5--------------------");
      String dlog_proof = p1Round4Ans + p2Round4Ans;
      int[] dlog_proof_length = {p1Round4Ans.length(), p2Round4Ans.length()};

      //party 1
      int[] p1Round5AnsLen = new int[1];
      String p1Round5Ans = instance.libmpecdsaKeygenRound5(ctx1, dlog_proof, dlog_proof_length,
          p1Round5AnsLen);
      System.out.println("party1 round5 ans " + p1Round5Ans);
      Assert.assertTrue(p1Round5Ans.length() == p1Round5AnsLen[0]);

      //party 2
      int[] p2Round5AnsLen = new int[1];
      String p2Round5Ans = instance.libmpecdsaKeygenRound5(ctx2, dlog_proof, dlog_proof_length,
          p2Round5AnsLen);
      System.out.println("party2 round5 ans " + p2Round5Ans);
      System.out.println("party2 round5 ans length " + p2Round5Ans.length());
      Assert.assertTrue(p2Round5Ans.length() == p2Round5AnsLen[0]);

      //lastly, party1 encrypt and store p1Round5Ans, and so does party2
    } catch (Throwable e) {
      e.printStackTrace();
      testResult = false;
    } finally {
      instance.libmpecdsaKeygenCtxFree(ctx1);
      instance.libmpecdsaKeygenCtxFree(ctx2);
      System.out.println("Free ctx successfully.");
      Assert.assertTrue(testResult);
    }
  }
}