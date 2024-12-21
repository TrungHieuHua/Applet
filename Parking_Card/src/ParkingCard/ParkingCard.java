package ParkingCard;

import javacard.framework.*;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;


public class ParkingCard extends Applet implements ExtendedLength {
    private Account account;
    private PIN pin;
    private CipherUtils cipherUtils;
    private Image image;
    private byte[] AES_KEY;
    private Cipher cipher;
    private KeyPair rsaKeyPair;
    private byte[] publicKey;
    private byte[] privateKey;
	
	
	// public static final byte CLA = 0xB0;
    public static final byte INS_RECEIVE_DATA = 0x01;
    public static final byte INS_SEND_DATA = 0x02;
    public static final byte INS_CREATE_PIN = 0x03;
    public static final byte INS_CHANGE_PIN = 0x04; 
    public static final byte INS_VERIFY = 0x05;
    public static final byte INS_UNLOCK = 0x06;     
    public static final byte INS_RECEIVE_MONEY = 0x10;
    public static final byte INS_SEND_MONEY = 0x11;
    public static final byte INS_ATTEMPTS_LEFT = 0x20;
    public static final byte INS_RECEIVE_IMAGE = 0x21;
    public static final byte INS_SEND_IMAGE = 0x22;
    public static final byte INS_SEND_PUBLIC_KEY = 0x30;
    public static final byte INS_AUTHENTICATE = 0x31;
    


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ParkingCard();
    }

    protected ParkingCard() {
    	cipherUtils = new CipherUtils();
        privateKey = new byte[256];
        publicKey = new byte[131];
        account = new Account();
        image = new Image();
        rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        pin = new PIN(cipherUtils);
        register();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }
        
        if (buffer[ISO7816.OFFSET_CLA] == (byte)0xA0) {
			if (buffer[ISO7816.OFFSET_INS] == INS_UNLOCK) {
				pin.unLockCard();
				return;
			} else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}
		
		if (pin.isLock) {
            ISOException.throwIt((short) 0x6985);
        }
		
        if (buffer[ISO7816.OFFSET_CLA] != (byte) 0xB0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_RECEIVE_DATA:
                saveAllData(apdu);
                break;
            case INS_SEND_DATA:
                readAllData(apdu);
                break;
             case INS_CREATE_PIN:
                 createPin(apdu);
                 break;
             case INS_CHANGE_PIN:
                changePin(apdu);
                break;
             case INS_VERIFY:
                 verifyPin(apdu);
                break;
             case INS_RECEIVE_MONEY:
                 receiveMoney(apdu);
                break;
             case INS_SEND_MONEY:
                 sendMoney(apdu);
                break;
             case INS_ATTEMPTS_LEFT:
                 getAttemptsLeft(apdu);
				break;
			case INS_RECEIVE_IMAGE:
                 receiveImage(apdu);
				break;
			case INS_SEND_IMAGE:
                 sendImage(apdu);
				break;
			case INS_SEND_PUBLIC_KEY:
                 sendPublicKey(apdu);
				break;
			case INS_AUTHENTICATE:
                 authenticate(apdu);
				break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    private void createPin(APDU apdu) {
         byte[] buffer = apdu.getBuffer();
         short dataLength = apdu.setIncomingAndReceive();
		
         if (dataLength < 6 || dataLength > 10) {
             ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
         }
         pin.setPin(buffer, ISO7816.OFFSET_CDATA, dataLength);
         generateKeyAes();
         generateKeyRsa();
         apdu.setOutgoingAndSend((short) 0, (short) 0);
     }
     
     private void receiveMoney(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();
        byte[]data = new byte [account.getMoneyLength()];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, data, (short)0, (short)account.getMoneyLength());
	    byte[] rawKey = cipherUtils.decryptAES(AES_KEY, pin.getPin());
	    cipherUtils.encryptAES(data, rawKey, data);
        account.saveMoney(data, (short)0);
        apdu.setOutgoingAndSend((short) 0, (short) 0);
     }
     
     private void sendMoney(APDU apdu) {
		byte[] data = account.getMoney();
		byte[] rawKeyAes = cipherUtils.decryptAES(AES_KEY, pin.getPin());	
		if(isDataEmpty(data))
			Util.arrayFillNonAtomic(data, (short)0, (short)account.getMoneyLength(),(byte) 0x00);
		else
			data = cipherUtils.decryptAES(data, rawKeyAes);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)account.getMoneyLength());
		apdu.sendBytesLong(data, (short)0, (short)account.getMoneyLength());
	}

    private void changePin(APDU apdu) {
         byte[] buffer = apdu.getBuffer();
         short dataLength = apdu.setIncomingAndReceive();
		
          if (dataLength < 6 || dataLength > 10) {
              ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		 }
		  byte[] rawKey = cipherUtils.decryptAES(AES_KEY, pin.getPin());
		  byte[] data = new byte [account.getTotalLength()];
		  byte[] money = account.getMoney();
		  byte[] rawPrivateKey = cipherUtils.decryptAES(privateKey, rawKey);
		  byte[] rawImage = cipherUtils.decryptAES(image.imageData, rawKey);// gia ma anh
		  account.readData(data, (short)0 ); // c d liu lên mng data
		  data = cipherUtils.decryptAES(data, rawKey);
		  money = cipherUtils.decryptAES(money, rawKey);
          pin.setPin(buffer, ISO7816.OFFSET_CDATA, dataLength);
          generateKeyAes();
          byte[] newRawKey = cipherUtils.decryptAES(AES_KEY, pin.getPin());
          cipherUtils.encryptAES(money, newRawKey, money); // mã hóa tin
          cipherUtils.encryptAES(data, newRawKey, data); // mã hóa thông tin
          account.saveData(data, (short) 0); // luu li thong tin
          account.saveMoney(money, (short)0); // luu lai tien
		  cipherUtils.encryptAES(rawPrivateKey, newRawKey, privateKey);// mã hóa private key
		  cipherUtils.encryptAES(rawImage, newRawKey, image.imageData); // mã hóa nh
          apdu.setOutgoingAndSend((short) 0, (short) 0);
     }

    
	private void getAttemptsLeft(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		buffer[0] = pin.getAttemptsLeft();
		apdu.setOutgoing();
		apdu.setOutgoingLength((byte) 1); // 1 byte vì attemptsLeft là kiu byte
		apdu.sendBytes((short) 0, (short) 1);
	}
	

    
     private void verifyPin(APDU apdu) {
         byte[] buffer = apdu.getBuffer();
         short pinLength = apdu.setIncomingAndReceive(); 
         boolean check = pin.verifyPin(buffer, ISO7816.OFFSET_CDATA, pinLength);
         if (check) {
             ISOException.throwIt((short) 0x9000); // Mã thành công
         } else {
             ISOException.throwIt((short) 0x6984); 
        }
     }
    
    
    private void readAllData(APDU apdu) {
		byte[] data = new byte[account.getTotalLength()];
        byte[] rawKey = cipherUtils.decryptAES(AES_KEY, pin.getPin());
        if(isDataEmpty(account.getId()))
			Util.arrayFillNonAtomic(data, (short)0, (short)account.getTotalLength(),(byte) 0x00);
        else{
	        account.readData(data, (short)0);
			data = cipherUtils.decryptAES(data, rawKey);
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) account.getTotalLength());
        apdu.sendBytesLong(data, (short) 0, account.getTotalLength());
    }
    
    private void saveAllData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();
        if (dataLength != account.getTotalLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte[] data = new byte[account.getTotalLength()];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, data, (short)0, (short)account.getTotalLength());
		byte[] rawKey = cipherUtils.decryptAES(AES_KEY, pin.getPin());
		cipherUtils.encryptAES(data, rawKey, data);
        account.saveData(data, (short) 0);
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }
    
     public void generateKeyAes()
	 {
		 byte[] rawKeyAes = cipherUtils.generateKeyAes();
		 AES_KEY = new byte[rawKeyAes.length];
		 cipherUtils.encryptAES(rawKeyAes, pin.getPin(), AES_KEY);
	 }
	 
	 public void generateKeyRsa()
	 {
		rsaKeyPair.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        storePublicKey(publicKey);
        storePrivateKey(privateKey);
	 }
	 private void receiveImage(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short recvLen = apdu.setIncomingAndReceive();
		short dataOffset = apdu.getOffsetCdata();

		Util.arrayFillNonAtomic(image.imageData, (short) 0, (short) image.imageData.length, (byte) 0x00);
		image.dataLength = 0;
		image.realLength = 0;

		while (recvLen > 0) {
			image.storeImage(buffer, dataOffset, recvLen);
			recvLen = apdu.receiveBytes(dataOffset);
		}
	
		short remainingSpace = (short)(5120 - image.dataLength);
		if (remainingSpace > 0) {
			Util.arrayFillNonAtomic(image.imageData, image.dataLength, remainingSpace, (byte) 0x00);
			image.dataLength = (short) 5120;
		}
		// ma hoa
		byte[] rawKey = cipherUtils.decryptAES(AES_KEY, pin.getPin());
        cipherUtils.encryptAES(image.imageData, rawKey, image.imageData);
	}

	private void sendImage(APDU apdu) {
		byte[] data = image.imageData;
		byte[] rawKey = cipherUtils.decryptAES(AES_KEY, pin.getPin()); // Khóa gii mã
		if(isDataEmpty(data))
			Util.arrayFillNonAtomic(data, (short)0, (short)image.getImageLength(),(byte) 0x00);
		else
			data = cipherUtils.decryptAES(data, rawKey);
		apdu.setOutgoing();
		apdu.setOutgoingLength(image.realLength);
		apdu.sendBytesLong(data, (short) 0, image.realLength);
	}
	
	private void sendPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (publicKey.length));
        apdu.sendBytesLong(publicKey, (short)0, (short) publicKey.length);
    }
    
    private void authenticate(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		RSAPrivateKey rawPrivateKey = restoreRSAPrivateKey(privateKey);
		short dataLength = apdu.getIncomingLength();
		byte[] rawMessage = new byte[(short)16];
		short len = (short) (dataLength - 16);
		byte[] encryptMessage = new byte[len];
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA , rawMessage, (short) 0, (short)16);
		Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + 16), encryptMessage, (short) 0, len);
        byte[] data = new byte[(short)128]; 
        cipher.init(rawPrivateKey, Cipher.MODE_DECRYPT);
        short decryptedLength = cipher.doFinal(encryptMessage, (short) 0, len, data, (short) 0);
        byte[] decryptedData  =new byte[decryptedLength];
        Util.arrayCopy(data, (short) 0, decryptedData, (short)0, decryptedLength); 
        short check = Util.arrayCompare(rawMessage, (short)0, decryptedData, (short)0, decryptedLength);
        if (check == 0) {
             ISOException.throwIt((short) 0x9000); 
         } else {
             ISOException.throwIt((short) 0x6984); 
        }
    }
    
    private void storePrivateKey(RSAPrivateKey rsaPrivateKey) {
		short keyLength = 0;
		keyLength += rsaPrivateKey.getModulus(privateKey, (short) 0);
		keyLength += rsaPrivateKey.getExponent(privateKey, keyLength);
		byte[] rawKeyAes = cipherUtils.decryptAES(AES_KEY, pin.getPin());
		cipherUtils.encryptAES(privateKey, rawKeyAes , privateKey);
	}
	private void storePublicKey(RSAPublicKey rsaPublicKey) {
		short keyLength = 0;
		keyLength += rsaPublicKey.getModulus(publicKey, (short) 0);
		keyLength += rsaPublicKey.getExponent(publicKey, keyLength);
	}

	private RSAPrivateKey restoreRSAPrivateKey(byte[] privateKey) {
		try {
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
			byte[] rawKeyAes = cipherUtils.decryptAES(AES_KEY, pin.getPin());
			byte[] rawPrivateKey = cipherUtils.decryptAES(privateKey, rawKeyAes);
			short offset = 0;
			short modulusLength = (short) (rawPrivateKey.length / 2); 
			rsaPrivateKey.setModulus(rawPrivateKey, offset, modulusLength);
			offset += modulusLength;
			short exponentLength = (short) (rawPrivateKey.length - offset);
			rsaPrivateKey.setExponent(rawPrivateKey, offset, exponentLength);
			return rsaPrivateKey;
		} catch (CryptoException e) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return null; 
		}
	}
	public boolean isDataEmpty(byte[] data) {
    for (short i = 0; i < data.length; i++) {
        if (data[i] != (byte) 0x00) {
            return false;
             }
    }
    return true; }
    
    
}