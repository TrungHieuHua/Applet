package ParkingCard;

import javacard.framework.*;
import javacard.framework.Util;import javacard.security.*;
import javacardx.apdu.ExtendedLength;

public class ParkingCard extends Applet implements ExtendedLength {
    private Account account;
    private PIN pin;
    private Image image;
    private byte[] AES_KEY;
    private RSAPublicKey PUBLIC_KEY;
    private RSAPrivateKey PRIVATE_KEY;
	
    public static final byte INS_RECEIVE_DATA = 0x01;
    public static final byte INS_SEND_DATA = 0x02;
    public static final byte INS_CREATE_PIN = 0x03;
    public static final byte INS_CHANGE_PIN = 0x04; 
    public static final byte INS_VERIFY = 0x05;    
    public static final byte INS_RECEIVE_MONEY = 0x10;
    public static final byte INS_SEND_MONEY = 0x11;
    public static final byte INS_ATTEMPTS_LEFT = 0x20;
    public static final byte INS_RECEIVE_IMAGE = 0x21;
    public static final byte INS_SEND_IMAGE = 0x22;


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ParkingCard();
    }

    protected ParkingCard() {
        pin = new PIN();
        account = new Account();
        image = new Image();
        register();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            return;
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
         apdu.setOutgoingAndSend((short) 0, (short) 0);
     }
     
     private void receiveMoney(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();
	    byte[] rawKey = CipherUtils.decryptAES(AES_KEY, pin.getPin());
        account.saveMoney(buffer, ISO7816.OFFSET_CDATA, rawKey);
        apdu.setOutgoingAndSend((short) 0, (short) 0);
     }
     
     private void sendMoney(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		byte[] rawKeyAes = CipherUtils.decryptAES(AES_KEY, pin.getPin());		
		account.readMoney(buffer, (short) 0, rawKeyAes);
		apdu.setOutgoingAndSend((short) 0, (short)account.getMoneyLength());
	}

    private void changePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();
		
         if (dataLength < 6 || dataLength > 10) {
             ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		 byte[] rawKey = CipherUtils.decryptAES(AES_KEY, pin.getPin());
		 byte[] data = new byte [account.getTotalLength()];
		 byte[] money =  new byte [account.getMoneyLength()];
		 account.readData(data, (short)0, rawKey );
		 account.readMoney(money, (short)0, rawKey);
         pin.setPin(buffer, ISO7816.OFFSET_CDATA, dataLength);
         generateKeyAes();
         byte[] newRawKey = CipherUtils.decryptAES(AES_KEY, pin.getPin());
         account.saveData(data, (short) 0, newRawKey);
         account.saveMoney(money, (short)0, newRawKey);
         apdu.setOutgoingAndSend((short) 0, (short) 0);
     }

    
	private void readPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();  
		byte[] pinData = pin.getPin();
		short len = (short) pinData.length;
		Util.arrayCopy(pinData, (short) 0, buffer, (short) 0, len);
		apdu.setOutgoingAndSend((short) 0, len);
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
             ISOException.throwIt((short) 0x6984); // Mã li PIN sai
        }
     }
    
    
    private void readAllData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        apdu.setIncomingAndReceive();
        byte[] rawKey = CipherUtils.decryptAES(AES_KEY, pin.getPin());
        account.readData(buffer, offset, rawKey);
        apdu.setOutgoingAndSend((short) 0, account.getTotalLength());
    }
    
    private void saveAllData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();

        if (dataLength != account.getTotalLength()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
		byte[] rawKey = CipherUtils.decryptAES(AES_KEY, pin.getPin());
        account.saveData(buffer, ISO7816.OFFSET_CDATA, rawKey);
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }
    
     public void generateKeyAes()
	 {
		 byte[] rawKeyAes = CipherUtils.generateKeyAes();
		 AES_KEY = new byte[rawKeyAes.length];
		 CipherUtils.encryptAES(rawKeyAes, pin.getPin(), AES_KEY);
	 }
	 
	 public void generateKeyRsa()
	 {
		 KeyPair keyPair = CipherUtils.generateRSAKeyPair();
		 PUBLIC_KEY = (RSAPublicKey) keyPair.getPublic();
		 PRIVATE_KEY = (RSAPrivateKey) keyPair.getPrivate();
	 }
	 //luu anh xuon the
	 private void receiveImage(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short recvLen = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();

        while (recvLen > 0) {
            image.storeImage(buffer, dataOffset, recvLen);
            recvLen = apdu.receiveBytes(dataOffset);
        }
    }

    // Gi d liu nh v máy tính
    private void sendImage(APDU apdu) {
        short dataLength = image.getImageLength();
        short le = apdu.setOutgoing();
        apdu.setOutgoingLength(dataLength);

        short pointer = 0;
        while (dataLength > 0) {
            short sendLen = (short) ((dataLength > le) ? le : dataLength);
            apdu.sendBytesLong(image.imageData, pointer, sendLen);
            pointer += sendLen;
            dataLength -= sendLen;
        }
    }
 }