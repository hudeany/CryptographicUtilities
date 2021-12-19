package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.soderer.utilities.worker.WorkerParentSimple;
import de.soderer.utilities.worker.WorkerSimple;

public class SymmetricDecryptionWorker extends WorkerSimple<Boolean> {
	private InputStream encryptedDataInputStream = null;
	private OutputStream decryptedDataOutputStream = null;
	private char[] password = null;
	private String encryptionMethod = null;
	private long dataSizeHint = -1;

	private final int randomSaltSize = 16;

	/**
	 * Symmetric decrypt inputStream
	 *
	 * @param parent
	 * @param encryptedDataInputStream
	 * @param decryptedDataOutputStream
	 * @param password
	 */
	public SymmetricDecryptionWorker(final WorkerParentSimple parent, final InputStream encryptedDataInputStream, final OutputStream decryptedDataOutputStream, final char[] password) {
		this(parent, encryptedDataInputStream, decryptedDataOutputStream, password, null);
	}

	/**
	 * Symmetric decrypt inputStream
	 *
	 * @param parent
	 * @param encryptedDataInputStream
	 * @param decryptedDataOutputStream
	 * @param password
	 * @param encryptionMethod
	 */
	public SymmetricDecryptionWorker(final WorkerParentSimple parent, final InputStream encryptedDataInputStream, final OutputStream decryptedDataOutputStream, final char[] password, final String encryptionMethod) {
		super(parent);
		this.encryptedDataInputStream = encryptedDataInputStream;
		this.decryptedDataOutputStream = decryptedDataOutputStream;
		this.password = password;
		this.encryptionMethod = encryptionMethod;

		if (isBlank(this.encryptionMethod)) {
			this.encryptionMethod = CryptographicUtilities.DEFAULT_SYMMETRIC_ENCRYPTION_METHOD;
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
		if ("TripleDES".equalsIgnoreCase(encryptionMethod) || "3DES".equalsIgnoreCase(encryptionMethod)) {
			encryptionMethod = "DESede";
		}
		encryptionMethod = encryptionMethod.toLowerCase();

		showProgress();

		itemsToDo = Math.max(dataSizeHint, encryptedDataInputStream.available());

		Security.addProvider(new BouncyCastleProvider());

		byte[] salt = null;
		byte[] initializationVector = null;
		try (OutputStream outputStream = new BufferedOutputStream(decryptedDataOutputStream)) {
			try (InputStream inputStream = new BufferedInputStream(encryptedDataInputStream)) {
				salt = new byte[randomSaltSize];
				final int readSaltBytes = inputStream.read(salt);
				if (readSaltBytes != salt.length) {
					throw new Exception("Cannot read password salt prefix: Data is too short");
				}

				final Cipher symetricDecryptCipher = Cipher.getInstance(encryptionMethod, BouncyCastleProvider.PROVIDER_NAME);
				final byte[] keyBytes = CryptographicUtilities.stretchPassword(password, 128, salt);
				final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, encryptionMethod);

				initializationVector = new byte[symetricDecryptCipher.getBlockSize()];
				final int readIvBytes = inputStream.read(initializationVector);
				if (readIvBytes != initializationVector.length) {
					throw new Exception("Cannot read initialization vector prefix: Data is too short");
				}

				symetricDecryptCipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(initializationVector));

				try (CipherInputStream cipherInputStream = new CipherInputStream(inputStream, symetricDecryptCipher)) {
					final int bufferSize = symetricDecryptCipher.getBlockSize() <= 0 ? 4096 : symetricDecryptCipher.getBlockSize();
					final byte[] buffer = new byte[bufferSize];
					int bytesRead;
					while ((bytesRead = cipherInputStream.read(buffer)) > -1) {
						if (cancel) {
							break;
						} else {
							outputStream.write(buffer, 0, bytesRead);
							itemsDone += bytesRead;
							showProgress();
						}
					}
				}

			}

			return true;
		} catch (final Exception e) {
			throw new Exception("Error while decrypting: " + e.getMessage(), e);
		} finally {
			clear(initializationVector);
			clear(salt);
		}
	}
}
