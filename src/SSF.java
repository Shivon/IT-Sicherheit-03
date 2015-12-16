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
  private byte[] encryptedInputFile;
  private byte[] encryptedAlgorithmParams;


  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.out.println("Usage: java SSF yourPrivateKey.prv opponentsPublicKey.pub originalFile encryptedFileName.ssf");
      return;
    }

    SSF ssf = new SSF();
    // get privateKey from file
    ssf.readKeyFromFile(args[0]);
    // get publicKey from file
    ssf.readKeyFromFile(args[1]);
    ssf.generateAESKey();
    ssf.signSecretKey();
    ssf.encryptSecretKey();
    // generate encrypted version of original file
    ssf.encryptFile(args[2]);
    // generate encrypted output file with signature
    ssf.generateSignedAndEncryptedFile(args[3]);

    System.out.println("public key: " + ssf.publicRSAKey);
    System.out.println("private key: " + ssf.privateRSAKey);
    System.out.println("encrypted secret key: " + ssf.encryptedSecretKey.toString());
    System.out.println("encrypted input file: " + ssf.encryptedInputFile.toString());
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
//      byte[] firstEncryptedBlock = cipher.update(aesKey.getEncoded());
//      encryptedSecretKey = concat(firstEncryptedBlock, cipher.doFinal(aesKey.getEncoded()));
      encryptedSecretKey = cipher.update(aesKey.getEncoded());
    } catch (NoSuchAlgorithmException e) {
      throw new Error("RSA not found for initializing cipher", e);
    } catch (InvalidKeyException e) {
      throw new Error("PublicRSAKey invalid", e);
    }
  }


  private void encryptFile(String inputFilePath) throws NoSuchPaddingException {
    encryptedInputFile = new byte[0];

    try {
      FileInputStream inputStream = new FileInputStream(inputFilePath);
      Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, aesKey);

      byte[] buffer = new byte[16];
      while ((inputStream.read(buffer)) > 0) {
        byte[] encryptedInputPart = cipher.update(buffer);
        // TODO: check if PKCS5Padding automatically fills up too short blocks
        encryptedInputFile = concat(encryptedInputFile, encryptedInputPart);
      }

      inputStream.close();
      encryptedAlgorithmParams = cipher.getParameters().getEncoded();
    } catch (NoSuchAlgorithmException e) {
      throw new Error("AES/CTR/PKCS5Padding not found for initializing cipher", e);
    } catch (InvalidKeyException e) {
      throw new Error("Secret aesKey invalid", e);
    } catch (IOException e) {
      throw new Error("Input file not found or invalid.", e);
    }
  }


  private byte[] concat(byte[] firstByteArray, byte[] secondByteArray) {
    byte[] resultArray = new byte[firstByteArray.length + secondByteArray.length];
    System.arraycopy(firstByteArray, 0, resultArray, 0, firstByteArray.length);
    System.arraycopy(secondByteArray, 0, resultArray, firstByteArray.length, secondByteArray.length);

    return resultArray;
  }


  private void generateSignedAndEncryptedFile(String outputFileName) throws IOException {
      DataOutputStream outputFile = new DataOutputStream(new FileOutputStream(outputFileName));

      outputFile.writeInt(encryptedSecretKey.length);
      outputFile.write(encryptedSecretKey);
      outputFile.writeInt(signatureBytesSecretKey.length);
      outputFile.write(signatureBytesSecretKey);
      outputFile.writeInt(encryptedAlgorithmParams.length);
      outputFile.write(encryptedAlgorithmParams);
      outputFile.write(encryptedInputFile);
  }
}
