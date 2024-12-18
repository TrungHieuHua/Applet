package ParkingCard;

import javacard.framework.*;
import javacard.security.*;


public class PIN {
    private byte[] pin; 
    private byte[] salt;
    private final byte maxAttempts = 3; 
    private byte attemptsLeft;
    public boolean isLock;

    public PIN() {
    	this.isLock = false;
	    this.salt = randomSalt();
	    this.attemptsLeft = -1;
    }
    
    public boolean verifyPin(byte[] inputPin, short offset, short length) {
    
		if (length < 6 || length > 10) {
			attemptsLeft -= 1;
			if(attemptsLeft <= 0)
			{
				lockCard();
				// ISOException.throwIt((short) 0x6710);
			}
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		byte[] rawPin = new byte[length];
		Util.arrayCopy(inputPin, offset, rawPin, (short) 0, length);
		byte[] hashedInputPin = CipherUtils.hashPin(rawPin, this.salt);
		short check = Util.arrayCompare(this.pin, (short) 0, hashedInputPin, (short) 0, (short) this.pin.length);
		if (check == 0) {
			attemptsLeft = maxAttempts; 
			return true; 
		} else {
			attemptsLeft--; 
			if (attemptsLeft <= 0) {
				lockCard();
				return false;
			}
			return false;
		}
	}

    
    public void setPin(byte[] newPin, short offset, short length) {
        if (newPin == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (length < 6 || length > 10) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        }
        byte[] rawPin= new byte[length];
        Util.arrayCopy(newPin, offset, rawPin, (short)0, length);
        this.isLock = false;
        this.salt = randomSalt();
        this.pin =  CipherUtils.hashPin(rawPin, this.salt);
        attemptsLeft = maxAttempts;  // Reset s ln th còn li
    }
   
    private static byte[] randomSalt() throws ISOException {
   
		byte[] salt = new byte[16];
		RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		randomData.generateData(salt, (short) 0, (short) salt.length);
		return salt;
	}
	
    public byte[] getPin() {
        return pin;
    }
   
	public byte getAttemptsLeft() {
        return attemptsLeft;
    }
	
    public byte getPinLength(){
	    return (byte)pin.length;
    }
    
    public void lockCard()
    {
	    this.isLock = true;
    }
}
