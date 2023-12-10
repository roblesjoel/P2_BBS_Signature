package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.FieldElement;
import ch.openchvote.util.sequence.ByteArray;
import ch.openchvote.util.sequence.Vector;
import ch.openchvote.util.tuples.Pair;
import com.herumi.mcl.Fr;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;
import java.util.stream.IntStream;

public class Scalar extends FieldElement<Scalar> {

    // Source: page 17 of https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-02
    public static final BigInteger MODULUS = new BigInteger("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001", 16);
    public static final int BYTE_LENGTH = 32;

    final Fr fr; // package privacy

    private Scalar(Fr fr) {
        this.fr = fr;
    }

    public static Scalar of(BigInteger value) {
        try {
            Fr fr = new Fr();
            fr.setStr(value.toString(16), 16);
            return new Scalar(fr);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException();
        }
    }

    public static Scalar getRandom() {
        Fr fr = new Fr();
        fr.setByCSPRNG();
        return new Scalar(fr);
    }

    public static Scalar deserialize(ByteArray byteArray) throws DeserializationException {
        try {
            Fr result = new Fr();
            result.deserialize(byteArray.toByteArray());
            return new Scalar(result);
        } catch (RuntimeException exception) {
            throw new DeserializationException(byteArray, exception);
        }
    }

    public static Scalar hashAndMap(Object input) {
        var string = input.toString();
        var byteArray = string.getBytes();
        var bigInt = new BigInteger(byteArray).mod(Scalar.MODULUS);
        return Scalar.of(bigInt);
    }

    public static Vector<Scalar> hashAndMap(Object input, int n) {
        var builder = new Vector.Builder<Scalar>();
        IntStream.rangeClosed(1, n)
                .mapToObj(i -> new Pair<>(input, i))
                .map(Scalar::hashAndMap)
                .forEach(builder::addValue);
        return builder.build();
    }

    public boolean biggerThan(Scalar other){
        BigInteger thisBigInt = new BigInteger(this.fr.toString(16), 16);
        if(thisBigInt.compareTo(other.toBigInteger()) == 1) return true;
        else if (thisBigInt.compareTo(other.toBigInteger()) == 0) return true;
        return false;
    }

    @Override
    public Scalar add(Scalar other) {
        Fr result = new Fr();
        Mcl.add(result, this.fr, other.fr);
        return new Scalar(result);
    }

    @Override
    public Scalar negate() {
        Fr result = new Fr();
        Mcl.neg(result, this.fr);
        return new Scalar(result);
    }

    @Override
    public boolean isZero() {
        return this.fr.isZero();
    }

    @Override
    public Scalar multiply(Scalar other) {
        Fr result = new Fr();
        Mcl.mul(result, this.fr, other.fr);
        return new Scalar(result);
    }

    @Override
    public Scalar power(Scalar exponent) {
        return of(this.toBigInteger().modPow(exponent.toBigInteger(), MODULUS));
    }

    @Override
    public Scalar inverse() {
        Fr result = new Fr();
        Mcl.inv(result, this.fr);
        return new Scalar(result);
    }

    @Override
    public boolean isOne() {
        return this.fr.isOne();
    }

    @Override
    public ByteArray serialize() {
        return ByteArray.of(this.fr.serialize());
    }

    @Override
    public BigInteger toBigInteger() {
        return new BigInteger(this.fr.toString(16), 16);
    }

    @Override
    public String toString() {
        String str = this.fr.toString(16);
        return "0".repeat(BYTE_LENGTH * 2 - str.length()) + str;
    }

}
