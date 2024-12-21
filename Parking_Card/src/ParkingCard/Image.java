package ParkingCard;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
class Image {
    public static final short MAX_SIZE = (short) 5120; 
    public byte[] imageData;
    public short realLength;
    public short dataLength;

    public Image() {
        imageData = new byte[MAX_SIZE];
        dataLength = 0;
        realLength = 0;
    }
    
    public void storeImage(byte[] buffer, short offset, short length) {
        Util.arrayCopy(buffer, offset, imageData, dataLength, length);
        dataLength += length;
        realLength += length;
    }

    public short getImageLength() {
        return dataLength;
    }
}