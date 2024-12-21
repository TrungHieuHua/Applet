package ParkingCard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
public class CipherUtils {
	 Cipher cipher;
	 AESKey aesKey;
	 MessageDigest md;
	 RandomData randomData;
     public CipherUtils()
     {
	     cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
	     aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
	     md = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
	     randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
     }
     public  void encryptAES(byte[] data, byte[] key, byte[] encryptedData) throws ISOException {
        try {
            aesKey.setKey(key, (short) 0);
            cipher.init(aesKey, Cipher.MODE_ENCRYPT);
            cipher.doFinal(data, (short) 0, (short) data.length, encryptedData, (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
     }
    public  byte[] decryptAES(byte[] encryptedData, byte[] key) throws ISOException {
        try {
        	byte[] decryptedData = new byte[encryptedData.length];
            aesKey.setKey(key, (short) 0);
            cipher.init(aesKey, Cipher.MODE_DECRYPT);
            cipher.doFinal(encryptedData, (short) 0, (short) encryptedData.length, decryptedData, (short) 0);
			return decryptedData;
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return null;
        }
    }


    public  byte[] generateKeyAes() {
        try {
        	byte[] input = random();
            md.update(input, (short) 0, (short) input.length);
            byte[] hashBytes = new byte[md.getLength()];
            md.doFinal(input, (short) 0, (short) input.length, hashBytes, (short) 0);
            return hashBytes;
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN); 
            return null; 
        }
    }


    public byte[] hashPin(byte[] rawPin, byte[] salt) {
        try {
            byte[] combined = new byte[(short) (rawPin.length + salt.length)];
            Util.arrayCopy(rawPin, (short) 0, combined, (short) 0, (short) rawPin.length);
            Util.arrayCopy(salt, (short) 0, combined, (short) rawPin.length, (short) salt.length);
            byte[] hash = new byte[md.getLength()];
            md.doFinal(combined, (short) 0, (short) combined.length, hash, (short) 0);
            return hash;  
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return null;
        }
    }

    private  byte[] random() throws ISOException {
   
		byte[] input = new byte[16];
		
		randomData.generateData(input, (short) 0, (short) input.length);
		return input;
	}   
}
