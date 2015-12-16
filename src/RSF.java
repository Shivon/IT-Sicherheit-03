import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.*;

class RSF {
	private PrivateKey privateRSAKey;
	private PublicKey publicRSAKey;
	private AlgorithmParameters algParams;
	private String encryptedFile;
	private String decryptedFile;
	private byte[] secretKeyBytes;
	private byte[] signature;

	public RSF(String encryptedFile, String decryptedFile) {
		this.encryptedFile = encryptedFile;
		this.decryptedFile = decryptedFile;
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

	public void decrypt() throws Exception {
		DataInputStream input = new DataInputStream(new FileInputStream(encryptedFile));
		int secretLength = input.readInt();
		byte[] encryptedSecretKey = new byte[secretLength];
		input.readFully(encryptedSecretKey);

		int signatureLength = input.readInt();
		System.out.println(signatureLength);
		signature = new byte[signatureLength];
		input.readFully(signature);

		int algorithmParamsLength = input.readInt();
		byte[] algorithmParamsBytes = new byte[algorithmParamsLength];
		input.readFully(algorithmParamsBytes);
		algParams = AlgorithmParameters.getInstance("AES");
		algParams.init(algorithmParamsBytes);
		decryptKey(encryptedSecretKey);
		System.out.println(encryptedSecretKey);
		if (!checkSignature(signature)) {
			System.out.println("Signature isnt valid.");
			input.close();
			return;
		}
		input.close();
		decryptFile();
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

	private void decryptFile() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(secretKeyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, algParams);
		FileOutputStream outputFile;
		InputStream inputStream = new DataInputStream(new FileInputStream(encryptedFile));
		try {
			outputFile = new FileOutputStream(decryptedFile);
		} catch (FileNotFoundException e) {
			throw new Error("The File couldnt be found", e);
		}
		byte[] buffer = new byte[16];
		while ((inputStream.read(buffer)) > 0) {
			outputFile.write(cipher.update(buffer));
		}
		outputFile.write(cipher.doFinal());
		outputFile.close();
	}

	public boolean checkSignature(byte[] signature) throws Exception {
		Signature sha256sign = Signature.getInstance("SHA256withRSA");
		sha256sign.initVerify(publicRSAKey);
		sha256sign.update(secretKeyBytes);
		System.out.println("kkkkkk"+secretKeyBytes);
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
		rsf.decryptFile();
	}

	public void decryptKey(byte[] secretKey) throws IllegalBlockSizeException, BadPaddingException {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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
}
