package ch.bfh.evg.signature;

import ch.bfh.evg.bls12_381.Scalar;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

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
        return OctetString.valueOf(String.valueOf(value), StandardCharsets.UTF_16);
    }

    public static OctetString valueOf(Scalar value){
        return OctetString.valueOf(value.toString(), StandardCharsets.UTF_16);
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
}
