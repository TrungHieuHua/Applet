package ParkingCard;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

// Class ImageHandler: X lý lu tr và c d liu hình nh
class Image {
    public static final short MAX_SIZE = (short) 10240; // Kích thc ti a ca d liu nh
    public byte[] imageData;
    public short dataLength;

    public Image() {
        imageData = new byte[MAX_SIZE];
        dataLength = 0;
    }

    // Phng thc lu tr d liu nh
    public void storeImage(byte[] buffer, short offset, short length) {
        Util.arrayCopy(buffer, offset, imageData, dataLength, length);
        dataLength += length;
    }

    // Phng thc c d liu nh
    public short readImage(byte[] buffer, short offset, short maxLength) {
        short copyLength = (short) ((dataLength > maxLength) ? maxLength : dataLength);
        Util.arrayCopy(imageData, (short) 0, buffer, offset, copyLength);
        return copyLength;
    }

    // Ly  dài d liu nh
    public short getImageLength() {
        return dataLength;
    }
}