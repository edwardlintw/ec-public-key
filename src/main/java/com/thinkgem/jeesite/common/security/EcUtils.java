package com.thinkgem.jeesite.common.security;

import com.thinkgem.jeesite.common.utils.Encodes;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.FixedSecureRandom;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class EcUtils {

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    private static final BigInteger HALF_CURVE_ORDER  = CURVE_PARAMS.getN().shiftRight(1);

    public static byte[] secp256k1_derivePubKey(byte[] privKey){
        BigInteger d = new BigInteger(1, privKey);
        ECPoint q = CURVE_PARAMS.getG().multiply(d);
        return q.getEncoded(true);
    }

    public static byte[] bigIntegerToBytes(BigInteger b,int numBytes){
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start;
        if (biBytes.length == numBytes + 1){
            start = 1;
        } else {
            start = 0;
        }
        int length = Math.min(biBytes.length, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }

    private static byte[] encodeSignature(BigInteger r, BigInteger s) {
        return Arrays.concatenate(
                bigIntegerToBytes(r, 32),
                bigIntegerToBytes(s, 32)
        );
    }

    private static BigInteger[] secp256k1_decodeSignature(byte[] bytes) {
        BigInteger[] bs = new BigInteger[2];
        byte[] buf = new byte[32];
        System.arraycopy(bytes, 0, buf, 0, 32);
        bs[0] = new BigInteger(1, buf);
        System.arraycopy(bytes, 32, buf, 0, 32);
        bs[1] = new BigInteger(1, buf);
        return bs;
    }


    public static byte[] secp256k1_sign(byte[] digest, byte[] privateKeyBytes){
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        BigInteger privateKey = new BigInteger(1, privateKeyBytes);
        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(privateKey, CURVE);
        signer.init(true, privKey);
        BigInteger[] components = signer.generateSignature(digest);
        if (components[0].compareTo(HALF_CURVE_ORDER)<=0) {
            components[1] = CURVE.getN().subtract(components[1]);
        }
        return encodeSignature(components[0], components[1]);
    }

    public static byte[] ecSign(ECPrivateKey key, byte[] data){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(data);
            return (secp256k1_sign(dig,key.getD().toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean secp256k1_verify(byte[] digest, byte[] pubKey, byte[] signature){
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new  ECPublicKeyParameters(CURVE.getCurve().decodePoint(pubKey), CURVE);
        signer.init(false, params);
        try {
            BigInteger[] sig = secp256k1_decodeSignature(signature);
            return signer.verifySignature(digest, sig[0], sig[1]);
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    public static boolean ecVerify(String keyStr, byte[] data, byte[] sig){
        Signature signer = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(data);
            return secp256k1_verify(dig,Encodes.decodeHex(keyStr),sig);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }


    public static ECPrivateKey toEcPrivKey(String keyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        ECPrivateKey privKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec( Encodes.decodeBase64(keyStr)));
        return privKey;
    }

    public static ECPublicKey toEcPubKey(String keyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        ECPublicKey pubKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec( Encodes.decodeBase64(keyStr)));
        return pubKey;
    }

    public static String toEcPrivKeyHex(String keyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        ECPrivateKey privKey = (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec ( Encodes.decodeBase64(keyStr)));
        String hexKey =  Encodes.encodeHex(privKey.getD().toByteArray());
        if(hexKey.startsWith("00") && (hexKey.length() == 66)){
            hexKey = hexKey.substring(2);
        }
        return hexKey;
    }

    public static String toEcPubKeyHex(String keyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        ECPublicKey pubKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec ( Encodes.decodeBase64(keyStr)));
        return Encodes.encodeHex(pubKey.getQ().getEncoded(true));
    }

}
