package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.soderer.utilities.worker.WorkerParentSimple;
import de.soderer.utilities.worker.WorkerSimple;

public class AsymmetricVerificationWorker extends WorkerSimple<Boolean> {
	private InputStream dataInputStream = null;
	private byte[] signatureData = null;
	private PublicKey publicKey = null;
	private String signatureMethod = null;
	private long dataSizeHint = -1;

	public AsymmetricVerificationWorker(final WorkerParentSimple parent, final InputStream dataInputStream, final byte[] signatureData, final PublicKey publicKey) {
		this(parent, dataInputStream, signatureData, publicKey, null);
	}

	public AsymmetricVerificationWorker(final WorkerParentSimple parent, final InputStream dataInputStream, final byte[] signatureData, final PublicKey publicKey, final String signatureMethod) {
		super(parent);
		this.dataInputStream = dataInputStream;
		this.signatureData = signatureData;
		this.publicKey = publicKey;
		this.signatureMethod = signatureMethod;

		if (isBlank(this.signatureMethod)) {
			this.signatureMethod = CryptographicUtilities.DEFAULT_SIGNATURE_METHOD_RSA;
		}
	}

	public void setDataSizeHint(final long dataSizeHint) {
		this.dataSizeHint = dataSizeHint;
	}

	@Override
	public Boolean work() throws Exception {
		signatureMethod = signatureMethod.toLowerCase();
		if (signatureMethod.endsWith("withec")) {
			signatureMethod = signatureMethod.replace("withec", "withecdsa");
		} else if (signatureMethod.endsWith("withecdh")) {
			signatureMethod = signatureMethod.replace("withecdh", "withecdsa");
		}

		showProgress();

		itemsToDo = Math.max(dataSizeHint, dataInputStream.available());

		Security.addProvider(new BouncyCastleProvider());

		try (BufferedInputStream dataStream = new BufferedInputStream(dataInputStream)) {
			final Signature signature = Signature.getInstance(signatureMethod, BouncyCastleProvider.PROVIDER_NAME);
			signature.initVerify(publicKey);
			final byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = dataStream.read(buffer)) >= 0) {
				if (cancel) {
					break;
				} else {
					signature.update(buffer, 0, bytesRead);
					itemsDone += bytesRead;
					showProgress();
				}
			}

			return signature.verify(signatureData);
		} catch (final Exception e) {
			throw new Exception("Cannot verify signature", e);
		}
	}
}
