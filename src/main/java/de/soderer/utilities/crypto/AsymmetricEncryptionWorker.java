package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.soderer.utilities.worker.WorkerParentSimple;
import de.soderer.utilities.worker.WorkerSimple;

public class AsymmetricEncryptionWorker extends WorkerSimple<Boolean> {
	private InputStream dataInputStream = null;
	private OutputStream encryptedDataOutputStream = null;
	private PublicKey publicKey = null;
	private String encryptionMethod = null;
	private long dataSizeHint = -1;

	/**
	 * Asymmetric encrypt inputStream
	 *
	 * @param parent
	 * @param fileToEncrypt
	 * @param encryptedFile
	 * @param publicKey
	 */
	public AsymmetricEncryptionWorker(final WorkerParentSimple parent, final InputStream dataInputStream, final OutputStream encryptedDataOutputStream, final PublicKey publicKey) {
		this(parent, dataInputStream, encryptedDataOutputStream, publicKey, null);
	}

	/**
	 * Asymmetric encrypt inputStream
	 *
	 * @param parent
	 * @param fileToEncrypt
	 * @param encryptedFile
	 * @param publicKey
	 * @param encryptionMethod
	 */
	public AsymmetricEncryptionWorker(final WorkerParentSimple parent, final InputStream dataInputStream, final OutputStream encryptedDataOutputStream, final PublicKey publicKey, final String encryptionMethod) {
		super(parent);
		this.dataInputStream = dataInputStream;
		this.encryptedDataOutputStream = encryptedDataOutputStream;
		this.publicKey = publicKey;
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
			throw new Exception("Empty asymmetric encryption method");
		}
		encryptionMethod = encryptionMethod.toLowerCase();

		showProgress();

		itemsToDo = Math.max(dataSizeHint, dataInputStream.available());

		Security.addProvider(new BouncyCastleProvider());

		try (InputStream inputStream = new BufferedInputStream(dataInputStream)) {
			if (encryptionMethod.equalsIgnoreCase("ecies")) {
				final Cipher eciesCipher = Cipher.getInstance(encryptionMethod, BouncyCastleProvider.PROVIDER_NAME);
				eciesCipher.init(Cipher.ENCRYPT_MODE, publicKey);

				// CipherOutputStream must be closed at end for correct final block data
				try (CipherOutputStream cipherOutputStream = new CipherOutputStream(new BufferedOutputStream(encryptedDataOutputStream), eciesCipher)) {
					final int bufferSize = eciesCipher.getBlockSize() <= 0 ? 4096 : eciesCipher.getBlockSize();
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
			} else {
				AsymmetricBlockCipher asymmetricEncryptCipher;
				if (encryptionMethod.startsWith("rsa")) {
					asymmetricEncryptCipher = new RSAEngine();
				} else if (encryptionMethod.startsWith("elgamal")) {
					asymmetricEncryptCipher = new ElGamalEngine();
				} else {
					throw new Exception("Unknown asymmetric encryption cipher method: " + encryptionMethod);
				}

				if (encryptionMethod.contains("pkcs1")) {
					asymmetricEncryptCipher = new PKCS1Encoding(asymmetricEncryptCipher);
				} else if (encryptionMethod.contains("oaep")) {
					asymmetricEncryptCipher = new OAEPEncoding(asymmetricEncryptCipher);
				} else if (encryptionMethod.contains("iso9796")) {
					asymmetricEncryptCipher = new ISO9796d1Encoding(asymmetricEncryptCipher);
				} else if (encryptionMethod.contains("nopadding")) {
					// do no padding
				} else {
					throw new Exception("Unknown asymmetric encryption padding method: " + encryptionMethod);
				}

				asymmetricEncryptCipher.init(true, PublicKeyFactory.createKey(publicKey.getEncoded()));

				try (BufferedOutputStream bufferedEncryptedDataOutputStream = new BufferedOutputStream(encryptedDataOutputStream);) {
					final int bufferSize = asymmetricEncryptCipher.getInputBlockSize() <= 0 ? 4096 : asymmetricEncryptCipher.getInputBlockSize();
					final byte[] buffer = new byte[bufferSize];
					int bytesRead;
					while ((bytesRead = dataInputStream.read(buffer)) > -1) {
						if (cancel) {
							break;
						} else {
							bufferedEncryptedDataOutputStream.write(asymmetricEncryptCipher.processBlock(buffer, 0, bytesRead));
							itemsDone += bytesRead;
							showProgress();
						}
					}
				}
			}

			return true;
		} catch (final Exception e) {
			throw new Exception("Error while encrypting: " + e.getMessage(), e);
		}
	}
}
