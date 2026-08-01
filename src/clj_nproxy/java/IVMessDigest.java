package clj_nproxy.java;

public interface IVMessDigest {
  IVMessDigest copy();

  void update(byte[] data);

  byte[] digest(byte[] data);
}
