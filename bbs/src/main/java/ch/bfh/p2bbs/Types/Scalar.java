package ch.bfh.p2bbs.Types;

import java.math.BigInteger;
import java.util.Objects;

public class Scalar {
    public static Scalar INVALID = new Scalar();

    public final BigInteger value;

    public Scalar(BigInteger value){
        this.value = value;
    }

    public Scalar(){
        this.value = null;
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

    public Scalar add(Scalar other){
        return new Scalar(value.add(other.value));
    }

    public Scalar modInverse(BigInteger other){
        return new Scalar(value.modInverse(other));
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

    public boolean isInvalid(){
        return this.value == null;
    }

    public Scalar power(int exponent){
        return new Scalar(this.value.pow(exponent));
    }
    public Scalar substract(Scalar other){
        return new Scalar(this.value.subtract(other.value));
    }

    @Override
    public String toString() {
        return this.value.toString(16);
    }

    public boolean equals(Scalar other){
        return this.value.equals(other.value);
    }
}
