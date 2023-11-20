package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.FieldElement;
import ch.openchvote.util.sequence.ByteArray;
import com.herumi.mcl.Fp;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

public class FpElement extends FieldElement<FpElement> {

    // Source: page 17 of https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-02
    public static final BigInteger MODULUS = new BigInteger("1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB", 16);
    public static final int BYTE_LENGTH = 48;

    private final Fp fp;

    private FpElement(Fp fp) {
        this.fp = fp;
    }

    public static FpElement of(BigInteger value) {
        try {
            Fp fp = new Fp();
            fp.setStr(value.toString(16), 16);
            return new FpElement(fp);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException();
        }
    }

    public static FpElement getRandom() {
        Fp fp = new Fp();
        fp.setByCSPRNG();
        return new FpElement(fp);
    }

    public static FpElement deserialize(ByteArray byteArray) throws DeserializationException {
        try {
            Fp result = new Fp();
            result.deserialize(byteArray.toByteArray());
            return new FpElement(result);
        } catch (RuntimeException exception) {
            throw new DeserializationException(byteArray, exception);
        }
    }

    @Override
    public FpElement add(FpElement other) {
        Fp result = new Fp();
        Mcl.add(result, this.fp, other.fp);
        return new FpElement(result);
    }

    @Override
    public FpElement negate() {
        Fp result = new Fp();
        Mcl.neg(result, this.fp);
        return new FpElement(result);
    }

    @Override
    public boolean isZero() {
        return this.fp.isZero();
    }

    @Override
    public FpElement multiply(FpElement other) {
        Fp result = new Fp();
        Mcl.mul(result, this.fp, other.fp);
        return new FpElement(result);
    }

    @Override
    public FpElement power(FpElement exponent) {
        return of(this.toBigInteger().modPow(exponent.toBigInteger(), MODULUS));
    }

    @Override
    public FpElement inverse() {
        Fp result = new Fp();
        Mcl.inv(result, this.fp);
        return new FpElement(result);
    }

    @Override
    public boolean isOne() {
        return this.fp.isOne();
    }

    @Override
    public ByteArray serialize() {
        return ByteArray.of(this.fp.serialize());
    }

    @Override
    public BigInteger toBigInteger() {
        return new BigInteger(this.fp.toString(16), 16);
    }

    @Override
    public String toString() {
        String str = this.fp.toString(16);
        return "0".repeat(BYTE_LENGTH * 2 - str.length()) + str;
    }

}
