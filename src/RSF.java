import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.*;

class RSF {
	private PrivateKey privateRSAKey;
	private PublicKey publicRSAKey;
	private AlgorithmParameters algorithmParams;
	private String encryptedFile;
	private String decryptedFile;
	private byte[] secretKeyBytes;
	private byte[] signature;

	public RSF(String encryptedFile, String decryptedFile) {
		this.encryptedFile = encryptedFile;
		this.decryptedFile = decryptedFile;
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


	public void decrypt() throws Exception {
		DataInputStream inputStream = new DataInputStream(new FileInputStream(encryptedFile));

		int secretKeyLength = inputStream.readInt();
		byte[] encryptedSecretKey = new byte[secretKeyLength];
		inputStream.readFully(encryptedSecretKey);

		int signatureLength = inputStream.readInt();
		signature = new byte[signatureLength];
		inputStream.readFully(signature);

		int algorithmParamsLength = inputStream.readInt();
		byte[] encryptedAlgorithmParams = new byte[algorithmParamsLength];
		inputStream.readFully(encryptedAlgorithmParams);
		algorithmParams = AlgorithmParameters.getInstance("AES");
		algorithmParams.init(encryptedAlgorithmParams);

		decryptKey(encryptedSecretKey);

		if (!checkSignature(signature)) {
			System.out.println("Signature not valid.");
			inputStream.close();
			return;
		}

		decryptFile(inputStream);
	}


	public void decryptKey(byte[] secretKey) throws IllegalBlockSizeException, BadPaddingException {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateRSAKey);
			secretKeyBytes = cipher.doFinal(secretKey);
		} catch (NoSuchAlgorithmException e) {
			throw new Error("There is no such algorithm as RSA in decrypt Key", e);
		} catch (NoSuchPaddingException e) {
			throw new Error("Padding exception in decrypt Key", e);
		} catch (InvalidKeyException e) {
			throw new Error("There is an invalid key", e);
		}
	}


	private void decryptFile(DataInputStream inputStream) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, algorithmParams);

		FileOutputStream outputFile = new FileOutputStream(decryptedFile);

		byte[] buffer = new byte[16];
		int inputLength;
		while ((inputLength = inputStream.read(buffer)) > 0) {
			outputFile.write(cipher.update(buffer, 0, inputLength));
		}

		inputStream.close();
		outputFile.close();
	}


	public boolean checkSignature(byte[] signature) throws Exception {
		Signature sha256sign = Signature.getInstance("SHA256withRSA");
		sha256sign.initVerify(publicRSAKey);
		sha256sign.update(secretKeyBytes);
		System.out.println("Secret key bytes: " + secretKeyBytes);
		return sha256sign.verify(signature);
	}


	public static void main(String[] args) throws Exception {
		if (args.length != 4) {
			System.out.println("Usage: java RSF yourPrivateKey.prv opponentsPublicKey.pub encryptedFileName.ssf decryptedFile");			return;
		}
		String encryptedFile = args[2];
		String decryptedFile = args[3];
		RSF rsf = new RSF(encryptedFile, decryptedFile);
		// get privateKey from file
		rsf.readKeyFromFile(args[0]);
		// get publicKey from file
		rsf.readKeyFromFile(args[1]);

		System.out.println("public key: " + rsf.publicRSAKey);
		System.out.println("private key: " + rsf.privateRSAKey);
		rsf.decrypt();
	}
}
