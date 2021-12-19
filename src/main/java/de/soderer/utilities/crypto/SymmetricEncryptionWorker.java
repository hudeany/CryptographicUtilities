package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.soderer.utilities.worker.WorkerParentSimple;
import de.soderer.utilities.worker.WorkerSimple;

public class SymmetricEncryptionWorker extends WorkerSimple<Boolean> {
	private InputStream dataInputStream = null;
	private OutputStream encryptedDataOutputStream = null;
	private char[] password = null;
	private String encryptionMethod = null;
	private long dataSizeHint = -1;

	private final int randomSaltSize = 16;

	/**
	 * Symmetric encrypt inputStream
	 *
	 * @param parent
	 * @param dataInputStream
	 * @param encryptedDataOutputStream
	 * @param password
	 */
	public SymmetricEncryptionWorker(final WorkerParentSimple parent, final InputStream dataInputStream, final OutputStream encryptedDataOutputStream, final char[] password) {
		this(parent, dataInputStream, encryptedDataOutputStream, password, null);
	}

	/**
	 * Symmetric encrypt inputStream
	 *
	 * @param parent
	 * @param dataInputStream
	 * @param encryptedDataOutputStream
	 * @param password
	 * @param encryptionMethod
	 */
	public SymmetricEncryptionWorker(final WorkerParentSimple parent, final InputStream dataInputStream, final OutputStream encryptedDataOutputStream, final char[] password, final String encryptionMethod) {
		super(parent);
		this.dataInputStream = dataInputStream;
		this.encryptedDataOutputStream = encryptedDataOutputStream;
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
			throw new Exception("Empty symmetric encryption method");
		}
		if ("TripleDES".equalsIgnoreCase(encryptionMethod) || "3DES".equalsIgnoreCase(encryptionMethod)) {
			encryptionMethod = "DESede";
		}
		encryptionMethod = encryptionMethod.toLowerCase();

		showProgress();

		itemsToDo = Math.max(dataSizeHint, dataInputStream.available());

		byte[] salt = null;
		byte[] initializationVector = null;
		try (InputStream inputStream = new BufferedInputStream(dataInputStream)) {
			try (OutputStream outputStream = new BufferedOutputStream(encryptedDataOutputStream)) {
				salt = new byte[randomSaltSize];
				new SecureRandom().nextBytes(salt);
				outputStream.write(salt);

				final byte[] keyBytes = CryptographicUtilities.stretchPassword(password, 128, salt);
				final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, encryptionMethod);
				final Cipher symetricEncryptCipher = Cipher.getInstance(encryptionMethod);

				initializationVector = new byte[symetricEncryptCipher.getBlockSize()];
				new SecureRandom().nextBytes(initializationVector);
				outputStream.write(initializationVector);

				symetricEncryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(initializationVector));

				// CipherOutputStream must be closed at end for correct final block data
				try (CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, symetricEncryptCipher)) {
					final int bufferSize = symetricEncryptCipher.getBlockSize() <= 0 ? 4096 : symetricEncryptCipher.getBlockSize();
					final byte[] buffer = new byte[bufferSize];
					int bytesRead;
					while ((bytesRead = inputStream.read(buffer)) > -1) {
						if (cancel) {
							break;
						} else {
							cipherOutputStream.write(buffer, 0, bytesRead);
							itemsDone += bytesRead;
							showProgress();
						}
					}
				}

				return true;
			}
		} catch (final Exception e) {
			throw new Exception("Error while encrypting: " + e.getMessage(), e);
		} finally {
			clear(initializationVector);
			clear(salt);
		}
	}
}
