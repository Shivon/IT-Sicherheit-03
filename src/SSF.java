import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;


class SSF {
  private PrivateKey privateRSAKey;
  private PublicKey publicRSAKey;
  private SecretKey aesKey;
  private byte[] signatureBytesSecretKey;
  private byte[] encryptedSecretKey;

  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      System.out.println("Usage: java SSF privateKey.prv publicKey.pub inputString outputString.ssf");
      return;
    }

    SSF ssf = new SSF();
    ssf.readKeyFromFile(args[0]);
    ssf.readKeyFromFile(args[1]);
    ssf.generateAESKey();
    ssf.signSecretKey();
    ssf.encryptSecretKey();

    System.out.println("public key: " + ssf.publicRSAKey);
    System.out.println("private key: " + ssf.privateRSAKey);
  }


  private void readKeyFromFile(String fileName) throws IOException {
    DataInputStream inputStream = new DataInputStream(new FileInputStream(fileName));

    // read and skip username
    int nameLength = inputStream.readInt();
    inputStream.skipBytes(nameLength);

    // read key from file
    int keyLength = inputStream.readInt();
    byte[] keyBytes = new byte[keyLength];
    inputStream.read(keyBytes);

    inputStream.close();

    // set public or private key
    if (fileName.endsWith(".prv")) {
      this.generatePrivateKeyFrom(keyBytes);
    } else if (fileName.endsWith(".pub")) {
      this.generatePublicKeyFrom(keyBytes);
    } else {
      throw new IOException("Unsupported file format - possible formats: .prv and .pub");
    }
  }


  private void generatePrivateKeyFrom(byte[] keyBytes) {
    PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory keyFactory;

    try {
      keyFactory = KeyFactory.getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
      throw new Error("No matching algorithm found", e);
    }

    try {
      privateRSAKey = keyFactory.generatePrivate(pkcs8KeySpec);
    } catch (InvalidKeySpecException e) {
      throw new Error("Can't create private key,invalid key spec", e);
    }
  }


  private void generatePublicKeyFrom(byte[] keyBytes) {
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory;

    try {
      keyFactory = KeyFactory.getInstance("RSA");
    } catch (NoSuchAlgorithmException e) {
      throw new Error("No matching algorithm found", e);
    }

    try {
      publicRSAKey = keyFactory.generatePublic(x509KeySpec);
    } catch (InvalidKeySpecException e) {
      throw new Error("Can't create public key,invalid key spec", e);
    }
  }


  private void generateAESKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(128);
    aesKey = keyGenerator.generateKey();
  }


  private void signSecretKey() {
    Signature signature;

    try {
      signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privateRSAKey);
      signature.update(aesKey.getEncoded());
      signatureBytesSecretKey = signature.sign();
    } catch (NoSuchAlgorithmException e) {
      throw new Error("SHA256withRSA not found for signature", e);
    } catch (InvalidKeyException e) {
      throw new Error ("Private RSA key not valid", e);
    } catch (SignatureException e) {
      throw new Error("Error occurred while signing the secret key", e);
    }
  }


  private void encryptSecretKey() throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException {
    try {
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, publicRSAKey);
      encryptedSecretKey = cipher.doFinal(aesKey.getEncoded());
    } catch (NoSuchAlgorithmException e) {
      throw new Error("RSA not found for initializing cipher", e);
    } catch (InvalidKeyException e) {
      throw new Error("PublicRSAKey invalid", e);
    }
  }
}
