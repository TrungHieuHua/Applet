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

    public void saveData(byte[] data, short offset) {
        Util.arrayCopy(data, offset, id, (short) 0, MAX_ID_LENGTH);
        Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH), fullName, (short) 0, MAX_NAME_LENGTH);
        Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH), dob, (short) 0, MAX_DOB_LENGTH);
        Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH), phone, (short) 0, MAX_PHONE_LENGTH);
		Util.arrayCopy(data, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH+ MAX_PHONE_LENGTH), numberCar, (short) 0, MAX_NUMBER_CAR_LENGTH);
    }

    public void readData(byte[] buffer, short offset) {        
        Util.arrayCopy(id, (short) 0, buffer, offset, MAX_ID_LENGTH);
        Util.arrayCopy(fullName, (short) 0, buffer, (short) (offset + MAX_ID_LENGTH), MAX_NAME_LENGTH);
        Util.arrayCopy(dob, (short) 0, buffer, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH), MAX_DOB_LENGTH);
        Util.arrayCopy(phone, (short) 0, buffer, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH), MAX_PHONE_LENGTH);
        Util.arrayCopy(numberCar, (short) 0, buffer, (short) (offset + MAX_ID_LENGTH + MAX_NAME_LENGTH+ MAX_DOB_LENGTH + MAX_PHONE_LENGTH), MAX_NUMBER_CAR_LENGTH);
    }


 
     public void saveMoney(byte[] data, short offset) {
        Util.arrayCopy(data, offset, money, (short) 0, MAX_MONEY_LENGTH);
    }
    public byte[] getMoney()
    {
	    return money;
    }
    
    public byte[] getId ()
    {
	    return id;
    }

    public short getTotalLength() {
        return (short) (MAX_ID_LENGTH + MAX_NAME_LENGTH + MAX_DOB_LENGTH + MAX_PHONE_LENGTH + MAX_NUMBER_CAR_LENGTH);
    }
    
    public short getMoneyLength() {
        return (short) (MAX_MONEY_LENGTH);
    }

}
