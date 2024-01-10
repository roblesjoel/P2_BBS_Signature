package ch.bfh.p2bbs.Types;

import java.math.BigInteger;
import java.util.Objects;

public class Scalar {
    public static Scalar INVALID = null;
    public static Scalar ABORT;

    public final BigInteger value;

    public Scalar(BigInteger value){
        this.value = value;
    }

    public boolean isInvalid(){
        return value == null;
    }

    public static Scalar of(BigInteger value) {
        return new Scalar(value);
    }

    public int signum(){
        return this.value.signum();
    }

    public int bitLength(){
        return this.value.bitLength();
    }

    public byte[] toByteArray(){
        return this.value.toByteArray();
    }

    public Scalar mod(BigInteger modVal){
        return Scalar.of(value.mod(modVal));
    }

    public BigInteger toBigInt(){
        return value;
    }

    public Scalar add(Scalar other){
        return new Scalar(value.add(other.value));
    }

    public Scalar modInverse(Scalar other){
        return new Scalar(value.modInverse(other.value));
    }

    public Scalar modInverse(BigInteger other){
        return new Scalar(value.modInverse(value));
    }

    public boolean isZero(){
        return Objects.equals(value, BigInteger.ZERO);
    }

    public int compareTo(BigInteger other){
        return value.compareTo(other);
    }

    public Scalar multiply(Scalar scalar){
        return new Scalar(value.multiply(scalar.value));
    }

    public Scalar negate(){
        return new Scalar(value.negate());
    }

    public boolean biggerOrSameThan(BigInteger other){
        return value.compareTo(other) >= 0;
    }
}
