package ParkingCard;

import javacard.framework.*;
import javacard.security.AESKey;

public class Account {

    private byte[] id;           
    private byte[] fullName;
    private byte[] dob;     
    private byte[] phone;      
    private byte[] numberCar;     
    private byte[] money; 

    private static final short MAX_ID_LENGTH = 16;
    private static final short MAX_NAME_LENGTH = 64;
    private static final short MAX_DOB_LENGTH = 16;
    private static final short MAX_PHONE_LENGTH = 16;
    private static final short MAX_NUMBER_CAR_LENGTH = 16;
    private static final short MAX_MONEY_LENGTH = 16;


    public Account() {
        id = new byte[MAX_ID_LENGTH];
        fullName = new byte[MAX_NAME_LENGTH];
        dob = new byte[MAX_DOB_LENGTH];
        phone = new byte[MAX_PHONE_LENGTH];
        numberCar = new byte[MAX_NUMBER_CAR_LENGTH];
        money = new byte[MAX_MONEY_LENGTH];
        
    }

    public void saveData(byte[] data, short offset, byte[] keyAes) {
        Util.arrayCopy(data, offset, id, (short) 0, MAX_ID_LENGTH);
        Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH), fullName, (short) 0, MAX_NAME_LENGTH);
        Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH), dob, (short) 0, MAX_DOB_LENGTH);
        Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH), phone, (short) 0, MAX_PHONE_LENGTH);
		Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH+ MAX_PHONE_LENGTH), numberCar, (short) 0, MAX_NUMBER_CAR_LENGTH);
        encryptAccountData(keyAes);
    }

    public void readData(byte[] buffer, short offset, byte[] key) {
        
        if (isDataEmpty(id) || isDataEmpty(fullName) || isDataEmpty(phone)) {
	        Util.arrayFillNonAtomic(buffer, offset, getTotalLength(), (byte) 0x00);
			return;
		}
        Util.arrayCopy(CipherUtils.decryptAES(id, key), (short) 0, buffer, offset, MAX_ID_LENGTH);
        Util.arrayCopy(CipherUtils.decryptAES(fullName, key), (short) 0, buffer, (short) (offset + MAX_ID_LENGTH), MAX_NAME_LENGTH);
        Util.arrayCopy(CipherUtils.decryptAES(dob, key), (short) 0, buffer, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH), MAX_DOB_LENGTH);
        Util.arrayCopy(CipherUtils.decryptAES(phone, key), (short) 0, buffer, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH), MAX_PHONE_LENGTH);
        Util.arrayCopy(CipherUtils.decryptAES(numberCar, key), (short) 0, buffer, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH+ MAX_DOB_LENGTH + MAX_PHONE_LENGTH), MAX_NUMBER_CAR_LENGTH);
    }


    private void encryptAccountData(byte[]key) {
        try {
            CipherUtils.encryptAES(id, key, id);
            CipherUtils.encryptAES(fullName, key, fullName);
            CipherUtils.encryptAES(dob, key, dob);
            CipherUtils.encryptAES(phone, key, phone);
            CipherUtils.encryptAES(numberCar, key, numberCar);
        } catch (ISOException e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
     public void saveMoney(byte[] data, short offset, byte[] key) {
        Util.arrayCopy(data, offset, money, (short) 0, MAX_MONEY_LENGTH);
		CipherUtils.encryptAES(money, key, money);
    }
    public void readMoney(byte[] buffer, short offset, byte[] key) {
    	if (isDataEmpty(money) ) {
			Util.arrayFillNonAtomic(buffer, offset, (short) getMoneyLength(), (byte) 0x00);
			return;
		 }
        Util.arrayCopy(CipherUtils.decryptAES(money, key), (short) 0, buffer, offset, MAX_MONEY_LENGTH);
    }

    public short getTotalLength() {
        return (short) (MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH + MAX_PHONE_LENGTH + MAX_NUMBER_CAR_LENGTH);
    }
    
    public short getMoneyLength() {
        return (short) (MAX_MONEY_LENGTH);
    }
    
    private boolean isDataEmpty(byte[] data) {
    for (short i = 0; i < data.length; i++) {
        if (data[i] != (byte) 0x00) {
            return false;
             }
    }
    return true; }
}
