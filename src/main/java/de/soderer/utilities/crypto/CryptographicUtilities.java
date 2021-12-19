package de.soderer.utilities.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ThreadLocalRandom;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import de.soderer.utilities.MapStringReader;
import de.soderer.utilities.collection.CaseInsensitiveMap;
import jdk.security.jarsigner.JarSigner;

/**
 * May need installed "US_export_policy.jar" and "local_policy.jar" for unlimited key strength Download: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
 */
public class CryptographicUtilities {
	public static final String[] SYMMETRIC_CIPHERS = {
			// Block chiffre
			"AES", "AESWrap", "Blowfish	", "Camellia", "CamelliaWrap", "CAST5", "CAST6", "DES", "DESede", "TripleDES", "3DES", "DESedeWrap", "GOST28147", "IDEA", "Noekeon", "RC2", "RC5", "RC5-64", "RC6", "Rijndael",
			"SEED", "SEEDWrap", "Serpent", "Skipjack", "TEA", "Twofish", "XTEA",

			// Stream chiffre
			"RC4", "HC128", "HC256", "Salsa20", "VMPC", "Grainv1", "Grain128" };

	public static final String DEFAULT_SYMMETRIC_ENCRYPTION_METHOD = "AES/CBC/PKCS7Padding";
	public static final String[] KNOWN_SYMMETRIC_ENCRYPTION_METHODS = new String[] {
			"AES/CBC/PKCS7Padding", "DES/CBC/PKCS5Padding", "DES/CBC/X9.23Padding", "DES/OFB8/NoPadding",
			"DES/ECB/WithCTS", "IDEA/CBC/ISO10126Padding", "IDEA/CBC/ISO7816-4Padding", "SKIPJACK/ECB/PKCS7Padding" };

	public static final String DEFAULT_SIGNATURE_METHOD_RSA = "SHA256WithRSA";
	public static final String[] KNOWN_SIGNATURE_METHODS_RSA = new String[] { "MD2withRSA", "MD5withRSA", "SHA1withRSA",
			"RIPEMD128withRSA", "RIPEMD160withRSA", "RIPEMD256withRSA", "SHA256withRSA", "SHA224withRSA", "SHA384withRSA",
			"SHA512withRSA", "SHA1withRSAandMGF1", "SHA256withRSAandMGF1", "SHA384withRSAandMGF1", "SHA512withRSAandMGF1" };

	public static final String DEFAULT_SIGNATURE_METHOD_EC = "SHA256withECDSA";
	public static final String[] KNOWN_SIGNATURE_METHODS_EC = new String[] { "RIPEMD160withECDSA", "SHA1withECDSA",
			"NONEwithECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA1withECNR",
			"SHA224withECNR", "SHA256withECNR", "SHA384withECNR", "SHA512withECNR" };

	public static final String[] KNOWN_SIGNATURE_METHODS_OTHERS = new String[] { "DSTU4145", "GOST3411withGOST3410", "GOST3411withGOST3410-94", "GOST3411withECGOST3410",
			"GOST3411withGOST3410-2001", "SHA1withDSA", "NONEwithDSA", };

	public static final String[] ASYMMETRIC_CIPHERS = new String[] { "RSA", "EC", "ElGamal" };

	public static final String DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD_RSA = "RSA/ECB/PKCS1Padding";
	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_RSA = new String[] {
			"RSA/NONE/PKCS1Padding",
			"RSA/NONE/OAEPPadding",
			"RSA/NONE/NoPadding",
			"RSA/NONE/PKCS1Padding",
			"RSA/NONE/OAEPWithMD5AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA1AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA224AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA256AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA384AndMGF1Padding",
			"RSA/NONE/OAEPWithSHA512AndMGF1Padding",
			"RSA/NONE/ISO9796-1Padding"
	};

	public static final String DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD_EC = "ECIES";
	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_EC = new String[] {
			"ECIES"
	};

	public static final String DEFAULT_ASYMMETRIC_ENCRYPTION_METHOD_ELGAMAL = "ELGAMAL/NONE/PKCS1PADDING";
	public static final String[] KNOWN_ASYMMETRIC_ENCRYPTION_METHODS_ELGAMAL = new String[] {
			"ELGAMAL/NONE/NoPadding",
			"ELGAMAL/NONE/PKCS1PADDING",
	};

	public static final String DEFAULT_ELLIPTIC_CURVE_NAME = "secp256k1";
	public static final String[] KNOWN_ELLIPTIC_CURVE_NAMES = new String[] {
			"secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1", "secp160r1", "secp160r2", "secp192k1",
			"secp192r1", //= prime192v1
			"prime192v1", //= secp192r1
			"secp224k1", "secp224r1",
			"secp256k1", //= Bitcoin
			"secp256r1", //= prime256v1
			"prime256v1", //= secp256r1
			"secp384r1", "secp521r1",
			"sect113r1", "sect113r2", "sect131r1", "sect131r2", "sect163k1", "sect163r1", "sect163r2", "sect193r1",
			"sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1",
			"sect571k1", "sect571r1"
	};

	public static KeyPair generateRsaKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateDsaKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateDhKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static KeyPair generateEcKeyPair(final String ecCurveName) throws Exception {
		if (ecCurveName == null || "".equals(ecCurveName.trim())) {
			throw new Exception("Missing EC curve name parameter");
		}

		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
			final ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecCurveName);
			keyGen.initialize(ecGenParameterSpec, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create EC keypair", e);
		}
	}

	public static KeyPair generateElGamalKeyPair(final int keyStrength) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", BouncyCastleProvider.PROVIDER_NAME);
			keyGen.initialize(keyStrength, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (final Exception e) {
			throw new Exception("Cannot create RSA keypair", e);
		}
	}

	public static X509Certificate generateSelfsignedCertificate(final KeyPair keyPair, final Date validFrom, final Date validUntil, final String signatureAlgorithm, final String subjectDN, final int allowedSubCaCertificateLevels) throws Exception {
		final Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);

		try {
			final X500Name dnName = new X500Name(subjectDN);
			final BigInteger certificateSerialNumber = new BigInteger(64, new SecureRandom());

			final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
			final JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(dnName, certificateSerialNumber, validFrom, validUntil, dnName, keyPair.getPublic());
			if (allowedSubCaCertificateLevels >= 0) {
				certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(allowedSubCaCertificateLevels));
			} else {
				certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			}
			return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateBuilder.build(contentSigner));
		} catch (final Exception e) {
			throw new Exception("Cannot create selfsigned certificate: " + e.getMessage(), e);
		}
	}

	public static String getStringFromX509Certificate(final X509Certificate certificate) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final StringWriter stringWriter = new StringWriter();
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
			pemWriter.writeObject(certificate);
		} catch (final Exception e) {
			throw new Exception("Cannot create certificate string: " + e.getMessage(), e);
		}
		return stringWriter.toString();
	}

	public static String getStringFromKeyPair(final AsymmetricCipherKeyPair keyPair, final char[] password) throws Exception {
		final PublicKey publicKey = getPublicKeyFromAsymmetricCipherKeyPair(keyPair);
		final PrivateKey privateKey = getPrivateKeyFromAsymmetricCipherKeyPair(keyPair);

		return getStringFromKeyPair(privateKey, password, publicKey);
	}

	public static String getStringFromKeyPair(final KeyPair keyPair, final char[] password) throws Exception {
		final PublicKey publicKey = keyPair.getPublic();
		final PrivateKey privateKey = keyPair.getPrivate();

		return getStringFromKeyPair(privateKey, password, publicKey);
	}

	public static String getStringFromKeyPair(final PrivateKey privateKey, final char[] password, final PublicKey publicKey) throws Exception {
		final StringBuilder result = new StringBuilder();
		result.append(getStringFromKey(privateKey, password));
		result.append(getStringFromKey(publicKey));
		return result.toString();
	}

	public static String getStringFromKey(final PublicKey publicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final StringWriter stringWriter = new StringWriter();
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
			pemWriter.writeObject(publicKey);
		} catch (final Exception e) {
			throw new Exception("Cannot create public key string: " + e.getMessage(), e);
		}
		return stringWriter.toString();
	}

	public static String getStringFromKey(final PrivateKey privateKey, final char[] password) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		if (password == null || password.length == 0) {
			final StringWriter stringWriter = new StringWriter();
			try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
				pemWriter.writeObject(privateKey);
			} catch (final Exception e) {
				throw new Exception("Cannot create private key string: " + e.getMessage(), e);
			}
			return stringWriter.toString();
		} else {
			final StringWriter stringWriter = new StringWriter();
			try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
				final OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
						.setProvider(BouncyCastleProvider.PROVIDER_NAME)
						.setRandom(new SecureRandom())
						.setPassword(password).build();
				pemWriter.writeObject(new JcaPKCS8Generator(privateKey, encryptor));
			} catch (final Exception e) {
				throw new Exception("Cannot create private key string: " + e.getMessage(), e);
			}
			return stringWriter.toString();
		}
	}

	public static AsymmetricCipherKeyPair getAsymmetricCipherKeyPair(final InputStream inputStream) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PEMKeyPair keyPair = getPEMKeyPairFromString(toString(inputStream, StandardCharsets.UTF_8));
		AsymmetricKeyParameter privateAsymmetricKeyParameter;
		if (keyPair.getPrivateKeyInfo() != null) {
			privateAsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
		} else {
			privateAsymmetricKeyParameter = null;
		}
		final AsymmetricKeyParameter publicAsymmetricKeyParameter;
		if (keyPair.getPublicKeyInfo() != null) {
			publicAsymmetricKeyParameter = PublicKeyFactory.createKey(keyPair.getPublicKeyInfo());
		} else {
			publicAsymmetricKeyParameter = null;
		}

		return new AsymmetricCipherKeyPair(publicAsymmetricKeyParameter, privateAsymmetricKeyParameter);
	}

	public static KeyPair getKeyPair(final InputStream inputStream) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PEMKeyPair keyPair = getPEMKeyPairFromString(toString(inputStream, StandardCharsets.UTF_8));
		AsymmetricKeyParameter privateAsymmetricKeyParameter;
		if (keyPair.getPrivateKeyInfo() != null) {
			privateAsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
		} else {
			privateAsymmetricKeyParameter = null;
		}
		final AsymmetricKeyParameter publicAsymmetricKeyParameter;
		if (keyPair.getPublicKeyInfo() != null) {
			publicAsymmetricKeyParameter = PublicKeyFactory.createKey(keyPair.getPublicKeyInfo());
		} else {
			publicAsymmetricKeyParameter = null;
		}

		final AsymmetricCipherKeyPair asymmetricCipherKeyPair = new AsymmetricCipherKeyPair(publicAsymmetricKeyParameter, privateAsymmetricKeyParameter);

		return new KeyPair(getPublicKeyFromAsymmetricCipherKeyPair(asymmetricCipherKeyPair), getPrivateKeyFromAsymmetricCipherKeyPair(asymmetricCipherKeyPair));
	}

	/**
	 * not tested yet
	 */
	public static KeyPair getKeyPairFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair asymmetricCipherKeyPair) throws Exception {
		final byte[] pkcs8Encoded = PrivateKeyInfoFactory.createPrivateKeyInfo(asymmetricCipherKeyPair.getPrivate()).getEncoded();
		final PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs8Encoded);
		final byte[] spkiEncoded = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(asymmetricCipherKeyPair.getPublic()).getEncoded();
		final X509EncodedKeySpec spkiKeySpec = new X509EncodedKeySpec(spkiEncoded);
		final KeyFactory keyFac = KeyFactory.getInstance("RSA");
		return new KeyPair(keyFac.generatePublic(spkiKeySpec), keyFac.generatePrivate(pkcs8KeySpec));
	}

	public static AsymmetricCipherKeyPair getAsymmetricCipherKeyPair(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PEMKeyPair keyPair = getPEMKeyPairFromString(getStringFromKeyPair(privateKey, null, publicKey));
		final AsymmetricKeyParameter privateAsymmetricKeyParameter = PrivateKeyFactory.createKey(keyPair.getPrivateKeyInfo());
		final AsymmetricKeyParameter publicAsymmetricKeyParameter = PublicKeyFactory.createKey(keyPair.getPublicKeyInfo());

		return new AsymmetricCipherKeyPair(privateAsymmetricKeyParameter, publicAsymmetricKeyParameter);
	}

	public static PublicKey getPublicKeyFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
	}

	public static PublicKey getPublicKeyFromKeyPair(final KeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent()));
	}

	public static PrivateKey getPrivateKeyFromAsymmetricCipherKeyPair(final AsymmetricCipherKeyPair keyPair) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
		final BigInteger exponent = ((RSAPrivateCrtKeyParameters) keyPair.getPrivate()).getExponent();
		//		final RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
		//		BigInteger exponent = publicKey.getExponent();
		return KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(privateKey.getModulus(), exponent, privateKey.getExponent(), privateKey.getP(), privateKey.getQ(),
				privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));
	}

	/**
	 * Generates Private Key from BASE64 encoded string
	 */
	public static PEMKeyPair getPEMKeyPairFromString(final String keyString) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (PEMParser pemReader = new PEMParser(new StringReader(keyString))) {
			final Object readObject = pemReader.readObject();
			pemReader.close();
			//			if (readObject instanceof PEMEncryptedKeyPair) {
			//                PEMEncryptedKeyPair pemEncryptedKeyPairKeyPair = (PEMEncryptedKeyPair) readObject;
			//                JcePEMDecryptorProviderBuilder jcePEMDecryptorProviderBuilder = new JcePEMDecryptorProviderBuilder();
			//                PEMKeyPair pemKeyPair = pemEncryptedKeyPairKeyPair.decryptKeyPair(jcePEMDecryptorProviderBuilder.build(keyPassword.toCharArray()));
			//            } else
			if (readObject instanceof PEMKeyPair) {
				final PEMKeyPair keyPair = (PEMKeyPair) readObject;
				return keyPair;
			} else if (readObject instanceof PrivateKeyInfo) {
				final PEMKeyPair keyPair = new PEMKeyPair(null, (PrivateKeyInfo) readObject);
				return keyPair;
			} else {
				return null;
			}
		} catch (final Exception e) {
			throw new Exception("Cannot read private key", e);
		}
	}

	/**
	 * Generates X509Certificate from BASE64 encoded string
	 */
	public static List<X509Certificate> getCertificatesFromString(final String certificateString) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try (PEMParser pemReader = new PEMParser(new StringReader(certificateString))) {
			final List<X509Certificate> returnList = new ArrayList<>();
			Object readObject;
			while ((readObject = pemReader.readObject()) != null)  {
				if (readObject instanceof X509Certificate) {
					returnList.add((X509Certificate) readObject);
				} else if (readObject instanceof X509CertificateHolder) {
					returnList.add(new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) readObject));
				}
			}
			return returnList;
		} catch (final Exception e) {
			throw new Exception("Cannot read certificate", e);
		}
	}

	/**
	 * Read a certificate file
	 */
	public static List<X509Certificate> getCertificatesFromFile(final File certificateFile) throws Exception {
		final String certificateFileString = readFileToString(certificateFile, StandardCharsets.UTF_8);
		return getCertificatesFromString(certificateFileString);
	}

	public static byte[] stretchPassword(final char[] password, final int keyLength, final byte[] salt) {
		Security.addProvider(new BouncyCastleProvider());

		final PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
		generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, 1000);
		final KeyParameter params = (KeyParameter) generator.generateDerivedParameters(keyLength);
		return params.getKey();
	}

	public static void otpWork(final byte[][] immutableData, final byte[][] mutableData) {
		for (int i = 0; i < mutableData.length - 1; i++) {
			getRandomByteArray(mutableData[i]);
		}
		final byte[] lastArray = mutableData[mutableData.length - 1];
		for (int i = 0; i < immutableData[0].length; i++) {
			lastArray[i] = 0;
			for (final byte[] element : immutableData) {
				lastArray[i] = (byte) (lastArray[i] ^ element[i]);
			}
			for (int j = 0; j < mutableData.length - 1; j++) {
				lastArray[i] = (byte) (lastArray[i] ^ mutableData[j][i]);
			}
		}
	}

	public static Set<String> getJarSignatureNames(final File jarFile) throws Exception {
		final Set<String> returnData = new HashSet<>();
		try (JarFile jar = new JarFile(jarFile)) {
			final Manifest manifest = jar.getManifest();
			if (manifest == null) {
				returnData.add("Has no MANIFEST.MF file");
				return returnData;
			}

			final byte[] buffer = new byte[4096];
			final Enumeration<JarEntry> jarEntriesEnumerator = jar.entries();

			while (jarEntriesEnumerator.hasMoreElements()) {
				final JarEntry jarEntry = jarEntriesEnumerator.nextElement();

				try (InputStream jarEntryInputStream = jar.getInputStream(jarEntry)) {
					// Reading the jarEntry throws a SecurityException if signature/digest check fails.
					while (jarEntryInputStream.read(buffer, 0, buffer.length) != -1) {
						// just read it
					}
				}

				if (!jarEntry.isDirectory()) {
					// Every file must be signed, except for files in META-INF
					final Certificate[] certificates = jarEntry.getCertificates();
					if ((certificates == null) || (certificates.length == 0)) {
						if (!jarEntry.getName().startsWith("META-INF")) {
							returnData.add("Contains unsigned files");
						}
					} else {
						for (final Certificate cert : certificates) {
							if (cert instanceof X509Certificate) {
								returnData.add(getValuesFromX500Principal(((X509Certificate) cert).getSubjectX500Principal()).get("CN"));
							} else {
								returnData.add("Unknown type of certificate");
							}
						}
					}
				}
			}

			return returnData;
		}
	}

	public static boolean verifyJarSignature(final File jarFile, final Collection<? extends Certificate> trustedCertificates) throws Exception {
		if (trustedCertificates == null || trustedCertificates.size() == 0) {
			return false;
		}

		try (JarFile jar = new JarFile(jarFile)) {
			final Manifest manifest = jar.getManifest();
			if (manifest == null) {
				throw new SecurityException("The jar file has no manifest, which contains the file signatures");
			}

			final byte[] buffer = new byte[4096];
			final Enumeration<JarEntry> jarEntriesEnumerator = jar.entries();

			while (jarEntriesEnumerator.hasMoreElements()) {
				final JarEntry jarEntry = jarEntriesEnumerator.nextElement();

				try (InputStream jarEntryInputStream = jar.getInputStream(jarEntry)) {
					// Reading the jarEntry throws a SecurityException if signature/digest check fails.
					while (jarEntryInputStream.read(buffer, 0, buffer.length) != -1) {
						// just read it
					}
				}

				if (!jarEntry.isDirectory()) {
					// Every file must be signed, except for files in META-INF
					final Certificate[] certificates = jarEntry.getCertificates();
					if ((certificates == null) || (certificates.length == 0)) {
						if (!jarEntry.getName().startsWith("META-INF")) {
							throw new SecurityException("The jar file contains unsigned files.");
						}
					} else {
						boolean isSignedByTrustedCert = false;

						for (final Certificate chainRootCertificate : certificates) {
							if (chainRootCertificate instanceof X509Certificate && verifyChainOfTrust((X509Certificate) chainRootCertificate, trustedCertificates)) {
								isSignedByTrustedCert = true;
								break;
							}
						}

						if (!isSignedByTrustedCert) {
							throw new SecurityException("The jar file contains untrusted signed files");
						}
					}
				}
			}

			return true;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	public static void removeJarSignature(final File signedTestJarFile, final File unsignedTestJarFile) throws Exception {
		removeFilesFromZipFile(signedTestJarFile, unsignedTestJarFile, StandardCharsets.UTF_8, "META-INF/*.RSA", "META-INF/*.SF");
	}

	public static void createJarSignature(final File unsignedJarFile, final PrivateKey privateKey, final CertPath certPath, final File signedJarFile) throws Exception {
		final JarSigner signer = new JarSigner.Builder(privateKey, certPath).build();
		try (ZipFile in = new ZipFile(unsignedJarFile);
				FileOutputStream out = new FileOutputStream(signedJarFile)) {
			signer.sign(in, out);
		}
	}

	public static CertPath createCertPath(final Certificate[] certs) throws Exception {
		return CertificateFactory.getInstance("X509").generateCertPath(Arrays.asList(certs));
	}

	/**
	 * Check if "certificate" was certified by "trustedCertificates"
	 *
	 * @param certificate
	 * @param trustedCertificates
	 * @return
	 * @throws Exception
	 */
	public static boolean verifyChainOfTrust(final X509Certificate certificate, final Collection<? extends Certificate> trustedCertificates) throws Exception {
		final X509CertSelector targetConstraints = new X509CertSelector();
		targetConstraints.setCertificate(certificate);

		final Set<TrustAnchor> trustAnchors = new HashSet<>();
		for (final Certificate trustedRootCert : trustedCertificates) {
			trustAnchors.add(new TrustAnchor((X509Certificate) trustedRootCert, null));
		}

		final PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, targetConstraints);
		params.setRevocationEnabled(false);
		try {
			final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(params);
			return result != null;
		} catch (@SuppressWarnings("unused") final Exception cpbe) {
			return false;
		}
	}

	/**
	 * Check if "certificate" was certified by "trustedCertificates"
	 *
	 * @param certificate
	 * @param trustedCertificates
	 * @return
	 * @throws Exception
	 */
	public static boolean verifyChainOfTrust(final X509Certificate certificate, final Certificate... trustedCertificates) throws Exception {
		final X509CertSelector targetConstraints = new X509CertSelector();
		targetConstraints.setCertificate(certificate);

		final Set<TrustAnchor> trustAnchors = new HashSet<>();
		for (final Certificate trustedRootCert : trustedCertificates) {
			trustAnchors.add(new TrustAnchor((X509Certificate) trustedRootCert, null));
		}

		final PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, targetConstraints);
		params.setRevocationEnabled(false);
		try {
			final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(params);
			return result != null;
		} catch (@SuppressWarnings("unused") final Exception cpbe) {
			return false;
		}
	}

	public static X509Certificate[] getChainRootCertificates(final Certificate[] certificates) {
		final Vector<X509Certificate> result = new Vector<>();
		for (int i = 0; i < certificates.length - 1; i++) {
			if (!((X509Certificate) certificates[i + 1]).getSubjectX500Principal().equals(((X509Certificate) certificates[i]).getIssuerX500Principal())) {
				result.addElement((X509Certificate) certificates[i]);
			}
		}
		// The final entry in the certificates array is always a root certificate
		result.addElement((X509Certificate) certificates[certificates.length - 1]);
		final X509Certificate[] returnValue = new X509Certificate[result.size()];
		result.copyInto(returnValue);
		return returnValue;
	}

	public static Collection<? extends X509Certificate> loadCertificatesFromPemStream(final InputStream pemInputStream) throws Exception {
		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		@SuppressWarnings("unchecked")
		final Collection<? extends X509Certificate> certificates = (Collection<? extends X509Certificate>) certificateFactory.generateCertificates(pemInputStream);
		return certificates;
	}

	public static CaseInsensitiveMap<String> getValuesFromX500Principal(final X500Principal x500Principal) throws Exception {
		return new CaseInsensitiveMap<>(MapStringReader.readMap(x500Principal.toString()));
	}

	public static boolean checkForCaCertificate(final X509Certificate certificate) {
		return certificate.getBasicConstraints() >= 0;
	}

	public static String getMd5FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(certificate.getEncoded());
		return toHexString(md.digest());
	}

	public static String getSha1FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(certificate.getEncoded());
		return toHexString(md.digest());
	}

	public static String getSha256FingerPrint(final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(certificate.getEncoded());
		return toHexString(md.digest());
	}

	public static String getMd5FingerPrint(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(key.getEncoded());
		return toHexString(md.digest());
	}

	public static String getSha1FingerPrint(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(key.getEncoded());
		return toHexString(md.digest());
	}

	public static String getSha256FingerPrint(final Key key) throws NoSuchAlgorithmException {
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(key.getEncoded());
		return toHexString(md.digest());
	}

	public static KeyPair convertPEMKeyPairToKeyPair(final PEMKeyPair keyPair) throws PEMException {
		try {
			String algorithm = keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm().getAlgorithm().getId();
			if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm)) {
				algorithm = "ECDSA";
			}

			final KeyFactory keyFactory = new DefaultJcaJceHelper().createKeyFactory(algorithm);

			return new KeyPair(
					keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublicKeyInfo().getEncoded())),
					keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivateKeyInfo().getEncoded())));
		} catch (final Exception e) {
			throw new PEMException("Unable to convert key pair: " + e.getMessage(), e);
		}
	}

	public static PrivateKey getPrivateKeyFromString(final String keyDataString, final char[] password) throws Exception {
		try {
			Security.addProvider(new BouncyCastleProvider());

			final PEMParser pemParser = new PEMParser(new StringReader(keyDataString));
			Object object;
			while ((object = pemParser.readObject()) != null) {
				if (object instanceof PEMKeyPair) {
					final PEMKeyPair pemKeyPair = (PEMKeyPair) object;
					if (password == null || password.length == 0) {
						final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
						final KeyPair keyPair = converter.getKeyPair(pemKeyPair);
						return keyPair.getPrivate();
					} else {
						throw new Exception("Unencrypted private key found. Password is obsolete.");
					}
				} else if (object instanceof PEMEncryptedKeyPair) {
					if (password == null || password.length == 0) {
						throw new MissingPasswordException("Encrypted private key found. Password is needed.");
					} else {
						final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
						final PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password);
						final KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
						return keyPair.getPrivate();
					}
				} else if (object instanceof PrivateKeyInfo) {
					if (password == null || password.length == 0) {
						final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
						return converter.getPrivateKey((PrivateKeyInfo) object);
					} else {
						throw new Exception("Unencrypted private key found. Password is obsolete.");
					}
				} else if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
					if (password == null || password.length == 0) {
						throw new MissingPasswordException("Encrypted private key (PKCS8) found. Password is needed.");
					} else {
						try {
							final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
							final InputDecryptorProvider decryptionProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password);
							final PrivateKeyInfo keyInfo = ((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(decryptionProv);
							return converter.getPrivateKey(keyInfo);
						} catch (final Exception e) {
							if (e instanceof PKCSException && e.getCause() != null && e.getCause() instanceof InvalidCipherTextIOException) {
								throw new WrongPasswordException();
							} else {
								throw e;
							}
						}
					}
				}
			}
			throw new Exception("No private key object found in data");
		} catch (final MissingPasswordException mpe) {
			throw mpe;
		} catch (final WrongPasswordException wpe) {
			throw wpe;
		} catch (final Exception e) {
			throw new Exception("Cannot read private key: " + e.getMessage(), e);
		}
	}

	public static PublicKey getPublicKeyFromString(final String keyDataString) throws Exception {
		try {
			Security.addProvider(new BouncyCastleProvider());

			final PEMParser pemParser = new PEMParser(new StringReader(keyDataString));
			Object object;
			while ((object = pemParser.readObject()) != null) {
				if (object instanceof PEMKeyPair) {
					final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
					final KeyPair keyPair = converter.getKeyPair((PEMKeyPair) object);
					return keyPair.getPublic();
				} else if (object instanceof SubjectPublicKeyInfo) {
					final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
					return converter.getPublicKey((SubjectPublicKeyInfo) object);
				}
			}
			throw new Exception("No public key object found in data");
		} catch (final Exception e) {
			throw new Exception("Cannot read public key: " + e.getMessage(), e);
		}
	}

	public static String getX509CertificateInfo(final X509Certificate certificate) throws Exception {
		String dataOutput = "";
		dataOutput += "CN: " + CryptographicUtilities.getValuesFromX500Principal(certificate.getSubjectX500Principal()).get("CN");
		dataOutput += "\n";
		dataOutput += "Subject: " + certificate.getSubjectX500Principal();
		dataOutput += "\n";
		dataOutput += "Issuer: " + certificate.getIssuerX500Principal();
		dataOutput += "\n";
		dataOutput += "is CA-certificate: " + (CryptographicUtilities.checkForCaCertificate(certificate) ? "true" : "false");
		dataOutput += "\n";
		dataOutput += "Valid from: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(certificate.getNotBefore());
		dataOutput += "\n";
		dataOutput += "Valid until: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(certificate.getNotAfter());
		dataOutput += "\n";
		dataOutput += "Signature algorithm: " + certificate.getSigAlgName();
		dataOutput += "\n";
		dataOutput += "Type: " + certificate.getType();
		dataOutput += "\n";
		dataOutput += "Version: " + certificate.getVersion();
		dataOutput += "\n";
		dataOutput += "Serial: " + certificate.getSerialNumber();
		dataOutput += "\n";
		dataOutput += "Key length: " + ((RSAKey) certificate.getPublicKey()).getModulus().bitLength();
		dataOutput += "\n";
		dataOutput += "MD5 fingerprint: " + CryptographicUtilities.getMd5FingerPrint(certificate);
		dataOutput += "\n";
		dataOutput += "SHA1 fingerprint: " + CryptographicUtilities.getSha1FingerPrint(certificate);
		dataOutput += "\n";
		dataOutput += "SHA256 fingerprint: " + CryptographicUtilities.getSha256FingerPrint(certificate);
		dataOutput += "\n";
		return dataOutput;
	}

	public static String getKeyInfo(final Key key) {
		String dataOutput = "";
		dataOutput += "Algorithm: " + key.getAlgorithm();
		dataOutput += "\n";

		if (key instanceof PrivateKey) {
			dataOutput += "Keytype: PrivateKey";
			dataOutput += "\n";
		} else if (key instanceof PublicKey) {
			dataOutput += "Keytype: PublicKey";
			dataOutput += "\n";
		}

		if (key instanceof RSAKey) {
			dataOutput += "Key length: " + ((RSAKey) key).getModulus().bitLength();
			dataOutput += "\n";
		} else if (key instanceof ECKey) {
			try {
				if (key instanceof PrivateKey) {
					dataOutput += "Elliptic Curve Name: " + getEllipticCurveName((PrivateKey) key);
					dataOutput += "\n";
				} else if (key instanceof PublicKey) {
					dataOutput += "Elliptic Curve Name: " + getEllipticCurveName((PublicKey) key);
					dataOutput += "\n";
				}
			} catch (@SuppressWarnings("unused") final Exception e) {
				dataOutput += "Elliptic Curve Name: Unknown";
				dataOutput += "\n";
			}
		}

		try {
			dataOutput += "MD5 fingerprint: " + CryptographicUtilities.getMd5FingerPrint(key);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "MD5 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA1 fingerprint: " + CryptographicUtilities.getSha1FingerPrint(key);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA1 fingerprint: Unknown";
		}
		dataOutput += "\n";

		try {
			dataOutput += "SHA256 fingerprint: " + CryptographicUtilities.getSha256FingerPrint(key);
		} catch (@SuppressWarnings("unused") final NoSuchAlgorithmException e) {
			dataOutput += "SHA256 fingerprint: Unknown";
		}
		dataOutput += "\n";

		return dataOutput;
	}

	public static boolean checkPrivateKeyFitsPublicKey(final PrivateKey privateKey, final PublicKey publicKey) throws Exception {
		final byte[] challenge = new byte[1024];
		ThreadLocalRandom.current().nextBytes(challenge);

		final Signature challengeSignature = Signature.getInstance("SHA512withRSA");
		challengeSignature.initSign(privateKey);
		challengeSignature.update(challenge);
		final byte[] signature = challengeSignature.sign();

		challengeSignature.initVerify(publicKey);
		challengeSignature.update(challenge);

		return challengeSignature.verify(signature);
	}

	public static String checkSignatureMethodName(final String signatureMethodName) {
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS_RSA) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS_EC) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		for (final String signatureMethodNameItem : KNOWN_SIGNATURE_METHODS_OTHERS) {
			if (signatureMethodNameItem.replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(signatureMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
				return signatureMethodNameItem;
			}
		}
		return null;
	}

	public static ASN1ObjectIdentifier getASN1ObjectIdentifierByEncryptionMethodName(final String encryptionMethodName) {
		try {
			for (final Field field : CMSAlgorithm.class.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()) && field.getName().replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(encryptionMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
					return (ASN1ObjectIdentifier) field.get(encryptionMethodName);
				}
			}
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static String checkEncryptionMethodName(final String encryptionMethodName) {
		try {
			for (final Field field : CMSAlgorithm.class.getDeclaredFields()) {
				if (Modifier.isStatic(field.getModifiers()) && field.getName().replace(" ", "").replace("_", "").replace("/", "").replace("-", "").equalsIgnoreCase(encryptionMethodName.replace(" ", "").replace("_", "").replace("/", "").replace("-", ""))) {
					return encryptionMethodName;
				}
			}
			return null;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static String generateLegacyX500PrincipalString(final String commonName, final String organizationalUnit, final String organizationName, final String location, final String state, final String country, final String email) throws Exception {
		final StringBuilder result = new StringBuilder();

		if (isNotBlank(commonName)) {
			result.append("CN=").append(commonName);
		} else {
			throw new Exception("CommonName(CN) is mandatory for X500Principal");
		}

		if (organizationalUnit != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("OU=").append(organizationalUnit);
		}

		if (organizationName != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("O=").append(organizationName);
		}

		if (location != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("L=").append(location);
		}

		if (state != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("ST=").append(state);
		}

		if (country != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("C=").append(country);
		}

		if (email != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("EMAILADDRESS=").append(email);
		}

		return result.toString();
	}

	public static String generateX500PrincipalString(final String commonName, final String organizationalUnit, final String organizationName, final String location, final String state, final String country, final String email) throws Exception {
		final StringBuilder result = new StringBuilder();

		if (isNotBlank(commonName)) {
			result.append("CN=").append(commonName);
		} else {
			throw new Exception("CommonName(CN) is mandatory for X500Principal");
		}

		if (organizationalUnit != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("OU=").append(organizationalUnit);
		}

		if (organizationName != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("O=").append(organizationName);
		}

		if (location != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("L=").append(location);
		}

		if (state != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("S=").append(state);
		}

		if (country != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("C=").append(country);
		}

		if (email != null) {
			if (result.length() > 0) {
				result.append(", ");
			}
			result.append("EMAILADDRESS=").append(email);
		}

		return result.toString();
	}

	public static Map<String, String> parseX500PrincipalString(final String x500NameString) {
		try {
			final Map<String, String> dataMap = MapStringReader.readMap(x500NameString);
			final LinkedHashMap<String, String> returnMap = new LinkedHashMap<>();
			for (final String keyName : new String[] { "CN", "OU", "O", "L", "S", "ST", "C", "E", "EMAIL", "EMAILADDRESS" }) {
				if (dataMap.containsKey(keyName)) {
					returnMap.put(keyName, dataMap.get(keyName));
				}
			}
			return returnMap;
		} catch (@SuppressWarnings("unused") final Exception e) {
			return null;
		}
	}

	public static PKCS10CertificationRequest generatePKCS10CertificationRequest(final PrivateKey privateKey, final PublicKey publicKey, final String commonName, final String organizationalUnit, final String organizationName, final String location, final String state, final String country, final String email) throws Exception {
		return generatePKCS10CertificationRequest(privateKey, publicKey, commonName, organizationalUnit, organizationName, location, state, country, email, DEFAULT_SIGNATURE_METHOD_RSA);
	}

	public static PKCS10CertificationRequest generatePKCS10CertificationRequest(final PrivateKey privateKey, final PublicKey publicKey, final String commonName, final String organizationalUnit, final String organizationName, final String location, final String state, final String country, final String email, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final PKCS10CertificationRequestBuilder certificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(generateX500PrincipalString(commonName, organizationalUnit, organizationName, location, state, country, email)), publicKey);
		final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signatureMethod);
		final ContentSigner contentSigner = contentSignerBuilder.build(privateKey);
		final PKCS10CertificationRequest certificationRequest = certificationRequestBuilder.build(contentSigner);

		return certificationRequest;
	}

	public static String getStringFromCertificationRequest(final PKCS10CertificationRequest certificationRequest) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final StringWriter writer = new StringWriter();
		try (final JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(writer)) {
			jcaPEMWriter.writeObject(certificationRequest);
		} catch (final Exception e) {
			throw new Exception("Cannot create certification signing request string: " + e.getMessage(), e);
		}
		return writer.toString();
	}

	public static PKCS10CertificationRequest getCertificationRequestFromString(final String encodedCertificationRequest) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		PKCS10CertificationRequest certificationRequest;
		try {
			final PEMParser pemParser = new PEMParser(new StringReader(encodedCertificationRequest));
			certificationRequest = (PKCS10CertificationRequest) pemParser.readObject();
		} catch (final IOException e) {
			throw new Exception("Error in reading the certificate signing request: " + e.getMessage(), e);
		}
		return certificationRequest;
	}

	public static X509Certificate signPKCS10CertificateRequest(final X509Certificate caCertificate, final PrivateKey caPrivateKey, final String caCrlEndpointUrl, final String caOcspEndpointUrl, final PKCS10CertificationRequest certificationRequest, final int allowedSubCaCertificateLevels, final BigInteger serialNo, final int validityDays) throws Exception {
		return signPKCS10CertificateRequest(caCertificate, caPrivateKey, caCrlEndpointUrl, caOcspEndpointUrl, certificationRequest, allowedSubCaCertificateLevels, serialNo, validityDays, DEFAULT_SIGNATURE_METHOD_RSA);
	}

	public static X509Certificate signPKCS10CertificateRequest(final X509Certificate caCertificate, final PrivateKey caPrivateKey, final String caCrlEndpointUrl, final String caOcspEndpointUrl, final PKCS10CertificationRequest certificationRequest, final int allowedSubCaCertificateLevels, final BigInteger serialNo, final int validityDays, final String signatureMethod) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		try {
			if (caCertificate.getBasicConstraints() < 0) {
				throw new Exception("Given certificate is not a CA certificate and therefore may not sign a Certificate Signing Requests");
			} else if (allowedSubCaCertificateLevels > -1 && caCertificate.getBasicConstraints() - 1 < allowedSubCaCertificateLevels) {
				throw new Exception("Given CA certificate with BasicConstraints value '" + caCertificate.getBasicConstraints() + "' may not sign a Certificate Signing Requests for a CA Certificate with BasicConstraints value '" + allowedSubCaCertificateLevels + "'");
			}

			final Date issuedDate = new Date();
			final Date expiryDate = new Date(System.currentTimeMillis() + validityDays * 86400000l);
			final JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(certificationRequest);
			final X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
					caCertificate,
					serialNo,
					issuedDate,
					expiryDate,
					jcaRequest.getSubject(),
					jcaRequest.getPublicKey());
			final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate));
			certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(jcaRequest.getPublicKey()));
			if (allowedSubCaCertificateLevels >= 0) {
				certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(allowedSubCaCertificateLevels));
			} else {
				certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			}
			certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
			certificateBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
			final ContentSigner signer = new JcaContentSignerBuilder(signatureMethod).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);

			if (isNotBlank(caCrlEndpointUrl)) {
				// Add CRL endpoint
				final DistributionPointName crlEp = new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, caCrlEndpointUrl)));
				final DistributionPoint disPoint = new DistributionPoint(crlEp, null, null);
				certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] { disPoint }));
			}

			if (isNotBlank(caOcspEndpointUrl)) {
				// Add OCSP endpoint
				final AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, caOcspEndpointUrl));
				final ASN1EncodableVector authInfoAccessASN = new ASN1EncodableVector();
				authInfoAccessASN.add(ocsp);
				certificateBuilder.addExtension(Extension.authorityInfoAccess, false, new DERSequence(authInfoAccessASN));
			}

			final X509Certificate signedCert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certificateBuilder.build(signer));
			return signedCert;
		} catch (final Exception e) {
			throw new Exception("Error in signing the certificate", e);
		}
	}

	public static boolean isCertificateFile(final File potentialCertificateFile) {
		if (potentialCertificateFile != null && potentialCertificateFile.exists()) {
			try {
				final String dataString = readFileToString(potentialCertificateFile, StandardCharsets.UTF_8);

				final String pemBegin = "-----BEGIN CERTIFICATE-----";
				final String pemEnd = "-----END CERTIFICATE-----";

				if (dataString.contains(pemBegin) && dataString.contains(pemEnd) && dataString.indexOf(pemBegin) < dataString.indexOf(pemEnd)) {
					return true;
				} else {
					return false;
				}
			} catch (@SuppressWarnings("unused") final Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}

	public static boolean isCertificationRequestFile(final File potentialCertificationRequestFile) {
		if (potentialCertificationRequestFile != null && potentialCertificationRequestFile.exists()) {
			try {
				final String dataString = readFileToString(potentialCertificationRequestFile, StandardCharsets.UTF_8);

				final String pemBegin = "-----BEGIN CERTIFICATE REQUEST-----";
				final String pemEnd = "-----END CERTIFICATE REQUEST-----";

				if (dataString.contains(pemBegin) && dataString.contains(pemEnd) && dataString.indexOf(pemBegin) < dataString.indexOf(pemEnd)) {
					return true;
				} else {
					return false;
				}
			} catch (@SuppressWarnings("unused") final Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}

	public static boolean isPrivateKeyFile(final File potentialPrivateKeyFile) {
		if (potentialPrivateKeyFile != null && potentialPrivateKeyFile.exists()) {
			try {
				final String dataString = readFileToString(potentialPrivateKeyFile, StandardCharsets.UTF_8);

				final String pemRsaBegin = "-----BEGIN RSA PRIVATE KEY-----";
				final String pemRsaEnd = "-----END RSA PRIVATE KEY-----";

				final String pemEcBegin = "-----BEGIN EC PRIVATE KEY-----";
				final String pemEcEnd = "-----END EC PRIVATE KEY-----";

				final String pemBegin = "-----BEGIN PRIVATE KEY-----";
				final String pemEnd = "-----END PRIVATE KEY-----";

				final String pemEncryptedBegin = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
				final String pemEncryptedEnd = "-----END ENCRYPTED PRIVATE KEY-----";

				if (dataString.contains(pemRsaBegin) && dataString.contains(pemRsaEnd) && dataString.indexOf(pemRsaBegin) < dataString.indexOf(pemRsaEnd)) {
					return true;
				} else if (dataString.contains(pemEcBegin) && dataString.contains(pemEcEnd) && dataString.indexOf(pemEcBegin) < dataString.indexOf(pemEcEnd)) {
					return true;
				} else if (dataString.contains(pemBegin) && dataString.contains(pemEnd) && dataString.indexOf(pemBegin) < dataString.indexOf(pemEnd)) {
					return true;
				} else if (dataString.contains(pemEncryptedBegin) && dataString.contains(pemEncryptedEnd) && dataString.indexOf(pemEncryptedBegin) < dataString.indexOf(pemEncryptedEnd)) {
					return true;
				} else {
					return false;
				}
			} catch (@SuppressWarnings("unused") final Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}

	public static boolean isPublicKeyFile(final File potentialPublicKeyFile) {
		if (potentialPublicKeyFile != null && potentialPublicKeyFile.exists()) {
			try {
				final String dataString = readFileToString(potentialPublicKeyFile, StandardCharsets.UTF_8);

				final String pemRsaBegin = "-----BEGIN RSA PUBLIC KEY-----";
				final String pemRsaEnd = "-----END RSA PUBLIC KEY-----";

				final String pemBegin = "-----BEGIN PUBLIC KEY-----";
				final String pemEnd = "-----END PUBLIC KEY-----";

				if (dataString.contains(pemRsaBegin) && dataString.contains(pemRsaEnd) && dataString.indexOf(pemRsaBegin) < dataString.indexOf(pemRsaEnd)) {
					return true;
				} else if (dataString.contains(pemBegin) && dataString.contains(pemEnd) && dataString.indexOf(pemBegin) < dataString.indexOf(pemEnd)) {
					return true;
				} else {
					return false;
				}
			} catch (@SuppressWarnings("unused") final Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}

	public static boolean isJavaKeyStoreFile(final File potentialJavaKeyStoreFile) {
		if (potentialJavaKeyStoreFile != null && potentialJavaKeyStoreFile.exists()) {
			try (InputStream keyStoreInputStream = new FileInputStream(potentialJavaKeyStoreFile)) {
				final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
				keyStore.load(keyStoreInputStream, null);
				return true;
			} catch (@SuppressWarnings("unused") final Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}

	public static PublicKey getPublicKeyFromPrivateKey(final PrivateKey privateKey) throws Exception {
		if (privateKey == null) {
			throw new Exception("Cannot extract PublicKey from empty PrivateKey");
		} else if (privateKey instanceof RSAPrivateCrtKey) {
			final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(((RSAPrivateCrtKey) privateKey).getModulus(), ((RSAPrivateCrtKey) privateKey).getPublicExponent());
			final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(publicKeySpec);
		} else if (privateKey instanceof org.bouncycastle.jce.interfaces.ECPrivateKey) {
			final org.bouncycastle.jce.interfaces.ECPrivateKey ecPrivateKey = (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
			final String name = getEllipticCurveName(ecPrivateKey);
			final KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
			final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
			final ECPoint Q = ecSpec.getG().multiply(ecPrivateKey.getD());
			final byte[] publicDerBytes = Q.getEncoded(false);
			final ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
			final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
			return keyFactory.generatePublic(pubSpec);
		} else if (privateKey instanceof java.security.interfaces.ECPrivateKey) {
			final java.security.interfaces.ECPrivateKey ecPrivateKey = (java.security.interfaces.ECPrivateKey) privateKey;
			final String name = getEllipticCurveName(ecPrivateKey);
			final KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
			final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
			final ECPoint Q = ecSpec.getG().multiply(ecPrivateKey.getS());
			final byte[] publicDerBytes = Q.getEncoded(false);
			final ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
			final ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
			return keyFactory.generatePublic(pubSpec);
		} else if (privateKey instanceof DSAPrivateKey) {
			throw new Exception("Cannot extract PublicKey from " + privateKey.getClass().getSimpleName());
		} else {
			throw new Exception("Cannot extract PublicKey from " + privateKey.getClass().getSimpleName());
		}
	}

	public static final String getEllipticCurveName(final PublicKey publicKey) throws GeneralSecurityException{
		if (publicKey instanceof java.security.interfaces.ECPublicKey){
			final java.security.interfaces.ECPublicKey pk = (java.security.interfaces.ECPublicKey) publicKey;
			final java.security.spec.ECParameterSpec params = pk.getParams();
			return getEllipticCurveName(EC5Util.convertSpec(params));
		} else if(publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey){
			final org.bouncycastle.jce.interfaces.ECPublicKey pk = (org.bouncycastle.jce.interfaces.ECPublicKey) publicKey;
			return getEllipticCurveName(pk.getParameters());
		} else {
			throw new IllegalArgumentException("This public key is no elliptic curve public key");
		}
	}

	public static final String getEllipticCurveName(final PrivateKey privateKey) throws GeneralSecurityException{
		if (privateKey instanceof java.security.interfaces.ECPrivateKey){
			final java.security.interfaces.ECPrivateKey pk = (java.security.interfaces.ECPrivateKey) privateKey;
			final java.security.spec.ECParameterSpec params = pk.getParams();
			return getEllipticCurveName(EC5Util.convertSpec(params));
		} else if(privateKey instanceof org.bouncycastle.jce.interfaces.ECPrivateKey){
			final org.bouncycastle.jce.interfaces.ECPrivateKey pk = (org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey;
			return getEllipticCurveName(pk.getParameters());
		} else {
			throw new IllegalArgumentException("This private key is no elliptic curve private key");
		}
	}

	public static final String getEllipticCurveName(final ECParameterSpec ecParameterSpec) throws GeneralSecurityException{
		for (final String name : Collections.list((Enumeration<String>) org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames())){
			final X9ECParameters params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(name);
			if (params.getN().equals(ecParameterSpec.getN())
					&& params.getH().equals(ecParameterSpec.getH())
					&& params.getCurve().equals(ecParameterSpec.getCurve())
					&& params.getG().equals(ecParameterSpec.getG())){
				return name;
			}
		}
		throw new GeneralSecurityException("Could not find elliptic curve name");
	}

	/**
	 * Uppercase hexadezimal display of ByteArray data
	 */
	private static String toHexString(final byte[] data) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();

		final char[] hexChars = new char[data.length * 2];
		for (int j = 0; j < data.length; j++) {
			final int v = data[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	private static String toString(final InputStream inputStream, final Charset encoding) throws IOException {
		return new String(toByteArray(inputStream), encoding);
	}

	private static byte[] toByteArray(final InputStream inputStream) throws IOException {
		if (inputStream == null) {
			return null;
		} else {
			try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
				copy(inputStream, byteArrayOutputStream);
				return byteArrayOutputStream.toByteArray();
			}
		}
	}

	private static long copy(final InputStream inputStream, final OutputStream outputStream) throws IOException {
		final byte[] buffer = new byte[4096];
		int lengthRead = -1;
		long bytesCopied = 0;
		while ((lengthRead = inputStream.read(buffer)) > -1) {
			outputStream.write(buffer, 0, lengthRead);
			bytesCopied += lengthRead;
		}
		outputStream.flush();
		return bytesCopied;
	}

	private static byte[] readFileToByteArray(final File dataFile) throws Exception {
		ByteArrayOutputStream output = null;
		try (FileInputStream input = new FileInputStream(dataFile)) {
			output = new ByteArrayOutputStream();
			copy(input, output);
			return output.toByteArray();
		} catch (final Exception e) {
			throw e;
		}
	}

	private static String readFileToString(final File dataFile, final Charset encoding) throws Exception {
		return new String(readFileToByteArray(dataFile), encoding);
	}

	/**
	 * Generate a random byteArray
	 *
	 * @param arrayToFill
	 * @return
	 */
	private static byte[] getRandomByteArray(final byte[] arrayToFill) {
		new SecureRandom().nextBytes(arrayToFill);
		return arrayToFill;
	}

	private static void removeFilesFromZipFile(final File originalZipFile, final File shrinkedZipFile, final Charset fileNameEncodingCharset, final String... filePatterns) throws Exception {
		try (ZipFile sourceZipFile = new ZipFile(originalZipFile);
				ZipOutputStream destinationZipOutputStream = openNewZipOutputStream(shrinkedZipFile, fileNameEncodingCharset)) {
			final List<Pattern> patternsToFilter = new ArrayList<>();
			for (final String filePattern : filePatterns) {
				patternsToFilter.add(Pattern.compile("^" + filePattern.replace("\\", "/").replace(".", "\\.").replace("*", ".*").replace("?", ".") + "$"));
			}

			final Enumeration<? extends ZipEntry> srcEntries = sourceZipFile.entries();
			while (srcEntries.hasMoreElements()) {
				final ZipEntry sourceZipFileEntry = srcEntries.nextElement();
				boolean keepFileEntry = true;
				for (final Pattern pattern : patternsToFilter) {
					if (pattern.matcher(sourceZipFileEntry.getName()).find()) {
						keepFileEntry = false;
						break;
					}
				}
				if (keepFileEntry) {
					destinationZipOutputStream.putNextEntry(sourceZipFileEntry);

					try (BufferedInputStream bufferedInputStream = new BufferedInputStream(sourceZipFile.getInputStream(sourceZipFileEntry))) {
						final byte[] bufferArray = new byte[4096];
						int byteBufferFillLength = bufferedInputStream.read(bufferArray);
						while (byteBufferFillLength > -1) {
							destinationZipOutputStream.write(bufferArray, 0, byteBufferFillLength);
							byteBufferFillLength = bufferedInputStream.read(bufferArray);
						}

						destinationZipOutputStream.closeEntry();
					}
				}
			}
		} catch (final IOException e) {
			throw e;
		}
	}

	/**
	 * Open a ZipOutputStream based on a file in which is written
	 *
	 * @param destinationZipFile
	 * @return
	 * @throws IOException
	 */
	private static ZipOutputStream openNewZipOutputStream(final File destinationZipFile, Charset fileNameEncodingCharset) throws IOException {
		if (destinationZipFile.exists()) {
			throw new IOException("DestinationFile already exists");
		} else if (!destinationZipFile.getParentFile().exists()) {
			throw new IOException("DestinationDirectory does not exist");
		}

		if (fileNameEncodingCharset == null) {
			fileNameEncodingCharset = Charset.forName("Cp437");
		}

		try {
			return new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(destinationZipFile)));
		} catch (final IOException e) {
			if (destinationZipFile.exists()) {
				destinationZipFile.delete();
			}
			throw e;
		}
	}

	private static boolean isBlank(final String value) {
		return value == null || value.length() == 0 || value.trim().length() == 0;
	}

	private static boolean isNotBlank(final String value) {
		return !isBlank(value);
	}
}
