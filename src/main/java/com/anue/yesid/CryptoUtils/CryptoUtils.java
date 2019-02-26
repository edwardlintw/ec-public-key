package com.anue.yesid.CryptoUtils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import com.thinkgem.jeesite.common.security.EcUtils;
import com.thinkgem.jeesite.common.utils.Encodes;

import craterdog.primitives.Tag;
import craterdog.security.MessageCryptex;
import craterdog.security.RsaAesMessageCryptex;
import craterdog.security.RsaCertificateManager;
import craterdog.utils.RandomUtils;

/**
 * CrytoUtils class to deal with all RSA/EC Cryptography issues
 * 
 * @author edwardlin
 *
 */
public class CryptoUtils {
  
  static { Security.addProvider(new BouncyCastlePQCProvider()); }
  
  public class RsaCertClass {
    public PrivateKey       privateKey;
    public PublicKey        publicKey;
    public X509Certificate  certificate;
  }
  
  public class EcCertClass {
    public ECPrivateKey     privateKey;
    public ECPublicKey      publicKey;
    public String           sanURI;     // alternative subject Name URI
  }
  
  private static CryptoUtils  cryptoUtils = null;
  
  private CryptoUtils() {
 
  }
  
  /**
   * used by CryptoUtils internal only
   * 
   * @return CryptoUtils instance
   */
  private static CryptoUtils getInstance() {
    if (null == cryptoUtils) {
      cryptoUtils = new CryptoUtils();
    }
    return cryptoUtils;
  }
  
  @Deprecated
  final static String BouncyCastleProvider         = "BC";
  final static public String EC_Key_SignAlgorithm  = "ECDSA";  // Elliptic Curve Digital Signature Algorithm
  final static public String RSA_Key_SignAlgorithm = "RSA";    // RSA Signature Algorithm

  /**
   * read p12-format input stream to retrieve EC Public Key / Private Key and Subject Alternative Name URI
   * 
   * @param input stream of p12 format
   * @return EcCertClass the composition of EC Private/Public Key and sanURI
   */
  public static EcCertClass readEcKeys(final InputStream p12)  {
    
    try {
      RsaCertificateManager manager    = new RsaCertificateManager();
      
      // load KeyStore
      KeyStore              ecKeyStore = manager.retrieveKeyStore(p12, "".toCharArray());
      
      // get pre-saved certificate and private key via alias `private`
      X509Certificate       cert       = manager.retrieveCertificate(ecKeyStore, "private");
      PrivateKey            priKey     = manager.retrievePrivateKey(ecKeyStore, "private", "".toCharArray());
      
      // retrieve public key from the certificate
      PublicKey             pubKey     = cert.getPublicKey();     
      // convert `PrivateKey` and `PublicKey` to `ECPrivateKey` and `ECPublicKey`, respectively
      
      EcCertClass   ecCert = CryptoUtils.getInstance().new EcCertClass();
      
      // transform byte stream to ECPublicKey / ECPrivateKey
      ecCert.privateKey = (ECPrivateKey)privateKeyFromBytes(priKey.getEncoded(), EC_Key_SignAlgorithm);
      ecCert.publicKey  = (ECPublicKey)publicKeyFromBytes(pubKey.getEncoded(), EC_Key_SignAlgorithm);
      
      // retrieve unique URI from certificate
      Collection<List<?>> subjItems = cert.getSubjectAlternativeNames();
      
      boolean uriFound = false;
      for (List<?> list : subjItems) {
        if (uriFound) 
          break;
        for (Object obj : list) {
          if (obj instanceof Integer && ((Integer) obj).intValue() == 6) {
            uriFound = true;
          }
          else if (obj instanceof String && uriFound) {
            ecCert.sanURI = obj.toString();
            break;
          }
        }
      }
      return ecCert;
    }
    catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  /**
   * 
   * @param input stream of p12 format
   * @return RsaCertClass the composition of RSA Private Key, Public Key and X509 Certificate
   */
  public static RsaCertClass readRsaKeys(final InputStream p12) {
    try {
      RsaCertificateManager manager    = new RsaCertificateManager();
      KeyStore              caKeyStore = manager.retrieveKeyStore(p12, "".toCharArray());
      RsaCertClass          rsaCert    = CryptoUtils.getInstance().new RsaCertClass();
      rsaCert.privateKey  = manager.retrievePrivateKey(caKeyStore, "private", "".toCharArray());
      rsaCert.certificate = manager.retrieveCertificate(caKeyStore, "private");
      rsaCert.publicKey   = rsaCert.certificate.getPublicKey();
      return rsaCert;
    }
    catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public static X509Certificate bytesToRsaCert(final byte[] bytes) {
  	InputStream inputStream = new ByteArrayInputStream(bytes);
  	return inputStreamToRsaCert(inputStream);
  }
  
  public static X509Certificate readRsaCert(final String certPem) {
		try {
			return inputStreamToRsaCert(new FileInputStream(certPem));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		}
  }
  
  public static X509Certificate readRsaCert(InputStream stream) {
		return inputStreamToRsaCert(stream);
  }
  
  public static X509Certificate inputStreamToRsaCert(final InputStream inputStream) {
		try {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return (X509Certificate)certFactory.generateCertificate(inputStream);
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		}
  }
 
  /**
   * transform byte stream into PrivateKey
   * 
   * @param bytes byte stream
   * @param algorithm one of EC_Key_SignAlgorithm/RSA_Key_SignAlgorithm, depends on KeySpec
   * @return PrivateKey the private key composed from byte stream, it may be one of RSA/EC key
   */
  public static PrivateKey privateKeyFromBytes(final byte[] bytes, final String algorithm) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
      return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(bytes));
    } 
    catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  }
  
  /**
   * transform byte stream into PublicKey
   * 
   * @param bytes byte stream
   * @param algorithm one of EC_Key_SignAlgorithm/RSA_Key_SignAlgorithm, depends on KeySpec
   * @return PublicKey the public key composed from byte stream, it may be one of RSA/EC key
   */
  public static PublicKey publicKeyFromBytes(final byte[] bytes, final String algorithm) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
      return keyFactory.generatePublic(new X509EncodedKeySpec(bytes));
    } 
    catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      e.printStackTrace();
      return null;
    }
  } 
    
  /**
   * sign message by RSA private key
   * 
   * @param privateKey RSA Private Key
   * @param algorithm given algorithm
   * @param msg message to sign
   * @return String base64 digital signature
   * @throws Exception
   */
  public static String signMessageWithRSA(final PrivateKey privateKey, final String algorithm, final String msg) throws Exception  {
    Signature privateSignature = Signature.getInstance(algorithm);
    privateSignature.initSign(privateKey);
    privateSignature.update(msg.getBytes("UTF-8"));
    byte[] s = privateSignature.sign();
    return Base64.getEncoder().encodeToString(s);
  }
  
  /**
   * sign message by EC private key by leveraging EcUtils.ecSign() methld
   * 
   * @param privateKey EC private key
   * @param msg to sign
   * @return Octet String of digit signature
   * @throws Exception
   */
  public static String signMessageWithECDSA(final ECPrivateKey privateKey, final String msg) throws Exception {
    return Encodes.encodeHex(EcUtils.ecSign(privateKey, msg.getBytes("UTF-8")));
  }
  
  /**
   * verify signature by RSA public key
   * 
   * @param pubKey RSA public key
   * @param data original message
   * @param signature digital signature
   * @param algorithm given algorithm
   * @return boolean result true/false
   * @throws Exception
   */
  public static boolean validateSignatureWithRSA(final String pubKey, final String data, final String signature, final String algorithm) throws Exception {
    Base64.Decoder  decoder = Base64.getDecoder();
    PublicKey       clientPublicKey = publicKeyFromBytes(decoder.decode(pubKey), CryptoUtils.RSA_Key_SignAlgorithm);
    return validateSignatureWithRSA(clientPublicKey, data, signature, algorithm);
  }

  public static boolean validateSignatureWithRSA(final PublicKey publicKey, final String data, final String signature, final String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
    Signature       publicSignature = Signature.getInstance(algorithm);
    publicSignature.initVerify(publicKey);
    publicSignature.update(data.getBytes("UTF-8"));
    return publicSignature.verify(Base64.getDecoder().decode(signature));
  }
  
  final protected long caCertificateLifetime = 30;      // years, can be overridden

  /**
   * this is an un-used old method; but which demonstrate how to
   * 1. generate private/public key pairs 
   * 2. create a self-signed RSA root certificate 
   */
  @Deprecated
  private void createCaRsaKeys(final String p12) {
    try (
          FileOutputStream output   = new FileOutputStream(p12);
        ) 
    {
       String           caSubject       = "CN=anue root CA, OU=YesID, O=anue, C=TW";
       BigInteger       caSerialNumber  = new BigInteger(RandomUtils.generateRandomBytes(8));
       long             lifetime        = caCertificateLifetime * 365L * 24L * 60L * 60L * 1000L; // milliseconds
       MessageCryptex   cryptex         = new RsaAesMessageCryptex();
       KeyPair          caKeyPair       = cryptex.generateKeyPair();
       
       PublicKey caPublicKey  = caKeyPair.getPublic();
       PrivateKey caPrivateKey = caKeyPair.getPrivate();
       RsaCertificateManager manager = new RsaCertificateManager();
       X509Certificate caCertificate = manager.createCertificateAuthority(caPrivateKey, caPublicKey, caSubject, caSerialNumber, lifetime);
       caCertificate.verify(caPublicKey);
       KeyStore   caKeyStore = manager.createPkcs12KeyStore("private", "".toCharArray(), caPrivateKey, caCertificate);
    
       manager.saveKeyStore(output, caKeyStore, "".toCharArray());
       
    } catch (Exception e) {
       e.printStackTrace();
    }
  }

  /**
   * This method demonstrates how to create Java KeyStore to store pre-generated ECPrivateKey/ECPublicKey by openssl
   */
  @Deprecated
  private void createEcKeysAndSave(final X509Certificate caCertificate, final PrivateKey caPrivateKey, final String prefix)  {
    /*
     * 1. openssl ecparam -name secp256k1 -genkey -noout -out private.pem
     * 2. trim beginning "-----BEGIN EC PRIVATE KEY-----" and trailing "-----END EC PRIVATE KEY-----"
     */
    final String ecPrivateB64 = "base64 from openssl private PEM file";
    /*
     * 1. openssl ec -in private.pem -pubout -out public.pem
     * 2. trim beginning "-----BEGIN PUBLIC KEY-----" and trailing "-----END PUBLIC KEY-----"
     */
    final String ecPublicB64  = "base64 from openssl public PEM file";

    /*
     * the password file (.pw) must exist
     */
    final String ecFile = prefix + ".ec.p12";
    final String pwFile = prefix + ".pw";
    try (
          FileOutputStream output   = new FileOutputStream(ecFile);
          FileReader       pwReader = new FileReader(pwFile);
      ) 
    {
      int     size       = new Tag(16).toString().length();
      char[]  caPassword = new char[size];
      
      pwReader.read(caPassword);

      /*
       * use RootCA (caCertificate) to create a dummy certificate, it offers 2 purposes
       * 1. for storing the private key
       * 2. for retrieving the public key
       * 
       * p.s. the subject `subject` is nonsense here, just an arbitrary one
       */
      String                subject       = "CN=A123456789, C=TW";
      long                  lifetime      = caCertificateLifetime * 365L * 24L * 60L * 60L * 1000L; // milliseconds
      BigInteger            serialNumber  = new BigInteger(RandomUtils.generateRandomBytes(4));
      RsaCertificateManager manager       = new RsaCertificateManager();
     
      /*
       * convert Base64 String `ecPrivateB64` and `ecPublicB64` to `ECPrivateKey` and `ECPublicKey` class representation
       */
      ECPrivateKey privateKey = (ECPrivateKey)CryptoUtils.privateKeyFromBytes(Base64.getDecoder().decode(ecPrivateB64), CryptoUtils.EC_Key_SignAlgorithm);
      ECPublicKey  publicKey  = (ECPublicKey)CryptoUtils.publicKeyFromBytes(Base64.getDecoder().decode(ecPublicB64), CryptoUtils.EC_Key_SignAlgorithm);

      /*
       * use existing RootCA `caCertificate`, RootCA private key `caPrivateKey` and EC public key `publicKey`
       * to generate and sign a client certificate
       */
      X509Certificate clientCert = manager.createCertificate(caPrivateKey, caCertificate, publicKey, subject, serialNumber, lifetime);
      clientCert.verify(caCertificate.getPublicKey());

      /*
       * save both generated certificate and pre-defined EC private key to store;
       * the public key can be retrieved from the certificate later
       */
      KeyStore  caKeyStore = manager.createPkcs12KeyStore("EC", caPassword, privateKey, clientCert);
      manager.saveKeyStore(output, caKeyStore, caPassword);
     
    } 
    catch (Exception e) {
     e.printStackTrace();
    }
  } 


}