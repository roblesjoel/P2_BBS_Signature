package ch.bfh.evg.signature;

import ch.bfh.evg.bls12_381.Scalar;
import ch.bfh.evg.group.GroupElement;
import ch.openchvote.util.sequence.ByteArray;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class OctetString {

    private final byte[] octetString;
    public final int length;

    public OctetString(){
        this.octetString = new byte[0];
        length = 0;
    }

    public OctetString(byte[] octetString){
        this.octetString = octetString;
        length = octetString.length;
    }

    public byte[] toBytes(){
        return octetString;
    }

    public OctetString concat(String str, Charset charset){
        return concat(valueOf(str, charset));
    }

    public OctetString concat(String str){
        return concat(valueOf(str));
    }

    public OctetString concat(OctetString str){
        byte[] otherBytes = str.toBytes();
        byte[] temp = new byte[otherBytes.length + this.octetString.length];
        System.arraycopy(this.octetString, 0, temp, 0, this.octetString.length);
        System.arraycopy(otherBytes, 0, temp, this.octetString.length, otherBytes.length);
        return new OctetString(temp);
    }

    public static OctetString valueOf(String value){
        return OctetString.valueOf(value, StandardCharsets.UTF_16);
    }

    public static OctetString valueOf(String value, Charset charset){
        return new OctetString(value.getBytes(charset));
    }

    public static OctetString valueOf(int value){
        return new OctetString(ByteBuffer.allocate(4).putInt(value).array());
    }

    public OctetString reverse(){
        byte[] b = new byte[length];
        int j = length;
        for (int i = 0; i < length; i++) {
            b[j - 1] = octetString[i];
            j = j - 1;
        }
        return new OctetString(b);
    }

    public static OctetString valueOf(Scalar value){
        return OctetString.valueOf(value.toString(), StandardCharsets.UTF_16);
    }

    public static OctetString valueOfHexString(String str){
        var temp = HexFormat.of().parseHex(str);
        return new OctetString(temp);
    }

    public OctetString split(int start, int end){
        int delta = end-start+1;
        byte[] temp = new byte[delta];
        System.arraycopy(octetString, start, temp, 0, delta);
        return new OctetString(temp);
    }

    public int toInt(){
        return ByteBuffer.wrap(octetString).getInt();
    }



    public Scalar toScalar() throws GroupElement.DeserializationException {
        return Scalar.deserialize(ByteArray.of(octetString));
    }

    @Override
    public String toString() {
        return bytesToHex(octetString);
    }

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }
}
