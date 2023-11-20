package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.FieldElement;
import ch.openchvote.util.sequence.ByteArray;
import ch.openchvote.util.sequence.Vector;
import ch.openchvote.util.tuples.Pair;
import com.herumi.mcl.Fr;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;
import java.util.stream.IntStream;

public class FrElement extends FieldElement<FrElement> {

    // Source: page 17 of https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-02
    public static final BigInteger MODULUS = new BigInteger("73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001", 16);
    public static final int BYTE_LENGTH = 32;

    final Fr fr; // package privacy

    private FrElement(Fr fr) {
        this.fr = fr;
    }

    public static FrElement of(BigInteger value) {
        try {
            Fr fr = new Fr();
            fr.setStr(value.toString(16), 16);
            return new FrElement(fr);
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException();
        }
    }

    public static FrElement getRandom() {
        Fr fr = new Fr();
        fr.setByCSPRNG();
        return new FrElement(fr);
    }

    public static FrElement deserialize(ByteArray byteArray) throws DeserializationException {
        try {
            Fr result = new Fr();
            result.deserialize(byteArray.toByteArray());
            return new FrElement(result);
        } catch (RuntimeException exception) {
            throw new DeserializationException(byteArray, exception);
        }
    }

    public static FrElement hashAndMap(Object input) {
        var string = input.toString();
        var byteArray = string.getBytes();
        var bigInt = new BigInteger(byteArray).mod(FrElement.MODULUS);
        return FrElement.of(bigInt);
    }

    public static Vector<FrElement> hashAndMap(Object input, int n) {
        var builder = new Vector.Builder<FrElement>();
        IntStream.rangeClosed(1, n)
                .mapToObj(i -> new Pair<>(input, i))
                .map(FrElement::hashAndMap)
                .forEach(builder::addValue);
        return builder.build();
    }

    @Override
    public FrElement add(FrElement other) {
        Fr result = new Fr();
        Mcl.add(result, this.fr, other.fr);
        return new FrElement(result);
    }

    @Override
    public FrElement negate() {
        Fr result = new Fr();
        Mcl.neg(result, this.fr);
        return new FrElement(result);
    }

    @Override
    public boolean isZero() {
        return this.fr.isZero();
    }

    @Override
    public FrElement multiply(FrElement other) {
        Fr result = new Fr();
        Mcl.mul(result, this.fr, other.fr);
        return new FrElement(result);
    }

    @Override
    public FrElement power(FrElement exponent) {
        return of(this.toBigInteger().modPow(exponent.toBigInteger(), MODULUS));
    }

    @Override
    public FrElement inverse() {
        Fr result = new Fr();
        Mcl.inv(result, this.fr);
        return new FrElement(result);
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
