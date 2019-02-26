package com.thinkgem.jeesite.modules.utils;

import com.thinkgem.jeesite.common.security.EcUtils;
import com.thinkgem.jeesite.common.utils.Encodes;
import com.thinkgem.jeesite.modules.messages.GTXOperation;
import com.thinkgem.jeesite.modules.messages.GTXTransaction;
import com.thinkgem.jeesite.modules.messages.GTXValue;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.openmuc.jasn1.ber.types.BerInteger;
import org.openmuc.jasn1.ber.types.BerOctetString;
import org.openmuc.jasn1.ber.types.string.BerUTF8String;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GtxUtils {

    public static byte[] getAsnPack(GTXTransaction tx){
        tx.code = null;
        try {
            tx.encodeAndSave(2048);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        byte[] txdata = new byte[tx.code.length + 1];
        txdata[0] = 0x30;
        System.arraycopy(tx.code,0,txdata,1,tx.code.length);
        System.out.println("Gtx::" +Encodes.encodeHex(txdata));
        return txdata;
    }

    public static byte[] digest(byte[] data){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static byte[] signGtx(GTXTransaction tx, ECPrivateKey privKey, byte[] pubKey){
        //填写signer
        //byte[] pubKey = EcUtils.secp256k1_derivePubKey(privKey.getD().toByteArray());
        GTXTransaction.Signers signers = tx.getSigners();
        signers.getBerOctetString().add(new BerOctetString(pubKey));


        //先打一个包
        byte[] txdata = getAsnPack(tx);
        if(txdata == null)
            return null;


        //对这个包进行签名

        byte[] txid = digest(txdata);

        //GTXTransaction
        GTXTransaction.Signatures signatures = tx.getSignatures();
        signatures.getBerOctetString().add(new BerOctetString(EcUtils.ecSign(privKey,txdata)));

        return txid;
    }

    public static void addArg(GTXOperation.Args args, Object arg) throws IOException {
      GTXValue v = new GTXValue();
      if(arg instanceof String){
        try {
          v.setString(new BerUTF8String((String) arg));
        } catch (UnsupportedEncodingException e) {
          e.printStackTrace();
          v.setString(new BerUTF8String());
        }
      }
      else if( arg instanceof Long){
        v.setInteger(new BerInteger((Long)arg));
      }
      else if (arg instanceof Integer) {
      	// Edward, treat integer as BigInteger, too
        v.setInteger(new BerInteger((Long)arg));
      }
      else if( arg instanceof byte[]){
        v.setByteArray(new BerOctetString((byte[]) arg));
      }
      else {
        throw new IOException("GtxUtils.addArg expects the `arg` is one of `String`, `byte[]`, `Long` and `Integer` type");
      }
      args.getGTXValue().add(v);
    }
}
