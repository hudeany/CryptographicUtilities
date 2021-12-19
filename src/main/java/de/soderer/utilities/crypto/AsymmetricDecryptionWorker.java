package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.soderer.utilities.worker.WorkerParentSimple;
import de.soderer.utilities.worker.WorkerSimple;

public class AsymmetricDecryptionWorker extends WorkerSimple<Boolean> {
	private InputStream encryptedDataInputStream = null;
	private OutputStream decryptedDataOutputStream = null;
	private PrivateKey privateKey = null;
	private String encryptionMethod = null;
	private long dataSizeHint = -1;

	/**
	 * Asymmetric decrypt inputStream
	 *
	 * @param parent
	 * @param fileToDecrypt
	 * @param decryptedFile
	 * @param privateKey
	 */
	public AsymmetricDecryptionWorker(final WorkerParentSimple parent, final InputStream encryptedDataInputStream, final OutputStream decryptedDataOutputStream, final PrivateKey privateKey) {
		this(parent, encryptedDataInputStream, decryptedDataOutputStream, privateKey, null);
	}

	/**
	 * Asymmetric decrypt inputStream
	 *
	 * @param parent
	 * @param fileToDecrypt
	 * @param decryptedFile
	 * @param privateKey
	 * @param encryptionMethod
	 */
	public AsymmetricDecryptionWorker(final WorkerParentSimple parent, final InputStream encryptedDataInputStream, final OutputStream decryptedDataOutputStream, final PrivateKey privateKey, final String encryptionMethod) {
		super(parent);
		this.encryptedDataInputStream = encryptedDataInputStream;
		this.decryptedDataOutputStream = decryptedDataOutputStream;
		this.privateKey = privateKey;
		this.encryptionMethod = encryptionMethod;

		if (isBlank(this.encryptionMethod)) {
			this.encryptionMethod = CryptographicUtilities.DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD_RSA;
		}
	}

	public void setDataSizeHint(final long dataSizeHint) {
		this.dataSizeHint = dataSizeHint;
	}

	@Override
	public Boolean work() throws Exception {
		if (encryptionMethod == null || "".equals(encryptionMethod.trim())) {
			throw new Exception("Empty symmetric decryption method");
		}
		encryptionMethod = encryptionMethod.toLowerCase();

		showProgress();

		itemsToDo = Math.max(dataSizeHint, encryptedDataInputStream.available());

		Security.addProvider(new BouncyCastleProvider());

		try (OutputStream outputStream = new BufferedOutputStream(decryptedDataOutputStream)) {
			if (encryptionMethod.equalsIgnoreCase("ecies")) {
				final Cipher decryptCipher = Cipher.getInstance(encryptionMethod, BouncyCastleProvider.PROVIDER_NAME);
				decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
				try (InputStream inputStream = new CipherInputStream(new BufferedInputStream(encryptedDataInputStream), decryptCipher)) {
					final int bufferSize = decryptCipher.getBlockSize() <= 0 ? 4096 : decryptCipher.getBlockSize();
					final byte[] buffer = new byte[bufferSize];
					int bytesRead;
					while ((bytesRead = inputStream.read(buffer)) > -1) {
						if (cancel) {
							break;
						} else {
							outputStream.write(buffer, 0, bytesRead);
							itemsDone += bytesRead;
							showProgress();
						}
					}
				}
			} else {
				AsymmetricBlockCipher decryptCipher;
				if (encryptionMethod.startsWith("rsa")) {
					decryptCipher = new RSAEngine();
				} else if (encryptionMethod.startsWith("elgamal")) {
					decryptCipher = new ElGamalEngine();
				} else {
					throw new Exception("Unknown asymmetric encryption cipher method: " + encryptionMethod);
				}
				if (encryptionMethod.contains("pkcs1")) {
					decryptCipher = new PKCS1Encoding(decryptCipher);
				} else if (encryptionMethod.contains("oaep")) {
					decryptCipher = new OAEPEncoding(decryptCipher);
				} else if (encryptionMethod.contains("iso9796")) {
					decryptCipher = new ISO9796d1Encoding(decryptCipher);
				} else if (encryptionMethod.contains("nopadding")) {
					// do no padding
				} else {
					throw new Exception("Unknown asymmetric encryption padding method: " + encryptionMethod);
				}

				decryptCipher.init(false, PrivateKeyFactory.createKey(privateKey.getEncoded()));

				try (InputStream inputStream = new BufferedInputStream(encryptedDataInputStream)) {
					final int bufferSize = decryptCipher.getInputBlockSize() <= 0 ? 4096 : decryptCipher.getInputBlockSize();
					final byte[] buffer = new byte[bufferSize];
					int bytesRead;
					while ((bytesRead = inputStream.read(buffer)) > -1) {
						if (cancel) {
							break;
						} else {
							outputStream.write(decryptCipher.processBlock(buffer, 0, bytesRead));
							itemsDone += bytesRead;
							showProgress();
						}
					}
				}
			}

			return true;
		} catch (final Exception e) {
			throw new Exception("Error while decrypting: " + e.getMessage(), e);
		}
	}
}
