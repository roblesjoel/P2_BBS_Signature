package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.ECPoint;
import ch.openchvote.util.sequence.ByteArray;
import com.herumi.mcl.G1;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

public class G1Point extends ECPoint<G1Point, FrElement, FpElement> {

    public static final G1Point GENERATOR = getGenerator();
    public static final G1Point ZERO = GENERATOR.subtract(GENERATOR);
    public static final int BYTE_LENGTH = 48;

    // Source: page 17-18 of https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-02
    private static final String x = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    private static final String y = "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    final G1 g1;  // package privacy

    private G1Point(G1 g1) {
        this.g1 = g1;
    }

    private static G1Point getGenerator() {
        G1 result = new G1();
        result.setStr(String.format("1 %s %s", x, y), 16);
        return new G1Point(result);
    }

    public static G1Point getRandom() {
        return GENERATOR.times(FrElement.getRandom());
    }

    public static G1Point deserialize(ByteArray byteArray) throws DeserializationException {
        try {
            G1 result = new G1();
            result.deserialize(byteArray.toByteArray());
            return new G1Point(result);
        } catch (RuntimeException exception) {
            throw new DeserializationException(byteArray, exception);
        }
    }

    public static G1Point hashAndMap(String message) {
        return hashAndMap(message.getBytes());
    }

    public static G1Point hashAndMap(byte[] message) {
        G1 result = new G1();
        Mcl.hashAndMapToG1(result, message);
        return new G1Point(result);
    }

    @Override
    public G1Point add(G1Point other) {
        G1 result = new G1();
        Mcl.add(result, this.g1, other.g1);
        return new G1Point(result);
    }

    @Override
    public G1Point times(FrElement scalar) {
        G1 result = new G1();
        Mcl.mul(result, this.g1, scalar.fr);
        return new G1Point(result);
    }

    @Override
    public G1Point negate() {
        G1 result = new G1();
        Mcl.neg(result, this.g1);
        return new G1Point(result);
    }

    public GTElement pair(G2Point other) {
        GT result = new GT();
        Mcl.pairing(result, this.g1, other.g2);
        return new GTElement(result);
    }

    @Override
    public boolean isZero() {
        return this.g1.isZero();
    }

    @Override
    public FpElement getX() {
        if (this.isZero()) {
            throw new UnsupportedOperationException();
        }
        return FpElement.of(new BigInteger(this.g1.toString(16).split(" ")[1], 16));
    }

    @Override
    public FpElement getY() {
        if (this.isZero()) {
            throw new UnsupportedOperationException();
        }
        return FpElement.of(new BigInteger(this.g1.toString(16).split(" ")[2], 16));
    }

    @Override
    public ByteArray serialize() {
        return ByteArray.of(this.g1.serialize());
    }

    @Override
    public String toString() {
        if (this.isZero()) {
            return INFINITY;
        } else {
            return String.format("x=%s y=%s", this.getX(), this.getY());
        }
    }

}
