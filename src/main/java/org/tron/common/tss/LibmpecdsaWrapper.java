package org.tron.common.tss;

import java.io.IOException;
import org.tron.common.util.Utils;

public class LibmpecdsaWrapper {
  private static final Libmpecdsa INSTANCE = new Libmpecdsa();

  static {
    try {
      System.load(Utils.getLibraryByName("libmpecdsajni"));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static Libmpecdsa getInstance() {
    return INSTANCE;
  }

}