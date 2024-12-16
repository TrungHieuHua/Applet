package ParkingCard;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
public class CipherUtils {

   
     public static void encryptAES(byte[] data, byte[] key, byte[] encryptedData) throws ISOException {
        try {
            Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            aesKey.setKey(key, (short) 0);
            cipher.init(aesKey, Cipher.MODE_ENCRYPT);
            short encryptedLength = cipher.doFinal(data, (short) 0, (short) data.length, encryptedData, (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
     }
    public static byte[] decryptAES(byte[] encryptedData, byte[] key) throws ISOException {
        try {
        	byte [] decryptedData = new byte[encryptedData.length];
            Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            aesKey.setKey(key, (short) 0);
            cipher.init(aesKey, Cipher.MODE_DECRYPT);
            cipher.doFinal(encryptedData, (short) 0, (short) encryptedData.length, decryptedData, (short) 0);
			return decryptedData;
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return null;
        }
    }

    public static byte[] addPKCS7Padding(byte[] data, short blockSize) {
		short paddingLength = (short)( blockSize - (data.length % blockSize));
		byte[] paddedData = new byte[data.length + paddingLength];
		Util.arrayCopy(data,(short) 0, paddedData,(short) 0,(short) data.length);
		for (short i = (short)data.length; i < (short)paddedData.length; i++) {
			paddedData[i] = (byte) paddingLength;
		}
		return paddedData;
	}

    public static byte[] removePKCS7Padding(byte[] data, short blockSize) {
		short paddingLength = data[data.length - 1];
		short dataLength = (short)(data.length - paddingLength);
		byte[] unpaddedData = new byte[dataLength];
		Util.arrayCopy(data, (short)0, unpaddedData, (short)0, (short)dataLength);

		return unpaddedData;
	}

    public static byte[] generateKeyAes() {
        try {
        	byte[] input = random();
            MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
            md.update(input, (short) 0, (short) input.length);
            byte[] hashBytes = new byte[md.getLength()];
            md.doFinal(input, (short) 0, (short) input.length, hashBytes, (short) 0);
            return hashBytes;
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN); 
            return null; 
        }
    }


    public static byte[] hashPin(byte[] rawPin, byte[] salt) {
        try {

            MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
            short iterations = 100;

            byte[] combined = new byte[(short) (rawPin.length + salt.length)];
            Util.arrayCopy(rawPin, (short) 0, combined, (short) 0, (short) rawPin.length);
            Util.arrayCopy(salt, (short) 0, combined, (short) rawPin.length, (short) salt.length);

            byte[] hash = new byte[md.getLength()];
            md.doFinal(combined, (short) 0, (short) combined.length, hash, (short) 0);
            byte[] storage = new byte[hash.length];

          
            for (short i = 0; i < iterations; i++) {
                Util.arrayCopy(hash, (short) 0, storage, (short) 0, (short) hash.length);
                md.doFinal(storage, (short) 0, (short) storage.length, hash, (short) 0);
            }

            return hash;  
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return null;
        }
    }

    public static KeyPair generateRSAKeyPair() {
        try {
            KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);  // RSA 2048 bit
            keyPair.genKeyPair();
            return keyPair;
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
            return null;
        }
    }

    public static short encryptRSA(RSAPublicKey publicKey, byte[] data, byte[]encryptedData) throws ISOException {
    try {
        Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipher.init(publicKey, Cipher.MODE_ENCRYPT);
        short len = cipher.doFinal(data, (short) 0, (short) data.length, encryptedData, (short) 0);
        return len;
    } catch (Exception e) {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
        return 0;
    }
	}


   public static short decryptRSA(RSAPrivateKey privateKey, byte[] encryptedData, byte[] decryptedData) throws ISOException {
    try {
        Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipher.init(privateKey, Cipher.MODE_DECRYPT);
        short len = cipher.doFinal(encryptedData, (short) 0, (short) encryptedData.length, decryptedData, (short) 0);
        return len;
    } catch (Exception e) {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
        return 0;
    }
	
}

    
    
    private static byte[] random() throws ISOException {
   
		byte[] input = new byte[16];
		RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		randomData.generateData(input, (short) 0, (short) input.length);
		return input;
	}

    
}
