package com.anue;

import java.security.Security;
import java.util.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import com.anue.yesid.CryptoUtils.*;
import com.thinkgem.jeesite.common.utils.Encodes;

public class App 
{
    public static void main( String[] args )
    {
    	Security.addProvider(new BouncyCastlePQCProvider());
    	if (0 == args.length)
        System.out.println("Hello World!");
    	else {
    		ECPublicKey ecPubKey = (ECPublicKey)CryptoUtils.publicKeyFromBytes(Base64.getDecoder().decode(args[0]), CryptoUtils.EC_Key_SignAlgorithm);
    		System.out.println(Encodes.encodeHex(ecPubKey.getQ().getEncoded(true)));
    	}
    }
}
