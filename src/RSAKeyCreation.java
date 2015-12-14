import java.io.*;
import java.security.*;
import java.security.spec.*;

class RSAKeyCreation {
  private String keyOwner;
  private KeyPair keyPair;
  private PrivateKey privateKey;
  private PublicKey publicKey;
  private byte[] privateKeyBytes;
  private byte[] publicKeyBytes;

  public RSAKeyCreation(String keyOwner) {
    this.keyOwner = keyOwner;
  }

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
    if (args.length == 0 || args.length > 1) {
      System.out.println("Usage: java RSAKeyCreation yourName");
      return;
    }

    RSAKeyCreation rsaKeyCreation = new RSAKeyCreation(args[0]);
    rsaKeyCreation.generateKeyPair();
    rsaKeyCreation.generateKeyFiles();
  }

  private void generateKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    keyPair = keyPairGen.generateKeyPair();

    privateKey = keyPair.getPrivate();
    publicKey = keyPair.getPublic();

    privateKeyBytes = privateKey.getEncoded();
    publicKeyBytes= publicKey.getEncoded();
  }

  private void generateKeyFiles() throws IOException {
    DataOutputStream privateKeyFile = new DataOutputStream(new FileOutputStream(keyOwner + ".prv"));
    DataOutputStream publicKeyFile = new DataOutputStream(new FileOutputStream(keyOwner + ".pub"));

    privateKeyFile.writeInt(keyOwner.length());
    publicKeyFile.writeInt(keyOwner.length());

    privateKeyFile.writeBytes(keyOwner);
    publicKeyFile.writeBytes(keyOwner);

    privateKeyFile.writeInt(privateKeyBytes.length);
    publicKeyFile.writeInt(publicKeyBytes.length);

    // format already PKCS8
    privateKeyFile.write(privateKeyBytes);
    // format already X.509
    publicKeyFile.write(publicKeyBytes);

    privateKeyFile.close();
    publicKeyFile.close();
  }
}
