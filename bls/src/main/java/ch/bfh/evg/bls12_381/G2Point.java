package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.ECPoint;
import ch.openchvote.util.sequence.ByteArray;
import ch.openchvote.util.tuples.Pair;
import com.herumi.mcl.G2;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

public class G2Point extends ECPoint<G2Point, Scalar, Pair<FpElement, FpElement>> {

    public static final G2Point GENERATOR = getGenerator();
    public static final G2Point ZERO = GENERATOR.subtract(GENERATOR);
    public static final int BYTE_LENGTH = 2 * 48;

    // Source: page 18 of https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-02
    private static final String x0 = "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    private static final String x1 = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    private static final String y0 = "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
    private static final String y1 = "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    final G2 g2;  // package privacy

    public G2Point(G2 g2) {
        this.g2 = g2;
    }

    private static G2Point getGenerator() {
        var result = new G2();
        result.setStr(String.format("1 %s %s %s %s", x0, x1, y0, y1), 16);
        return new G2Point(result);
    }

    public static G2Point getRandom() {
        return GENERATOR.times(Scalar.getRandom());
    }

    public static G2Point deserialize(ByteArray byteArray) throws DeserializationException {
        try {
            G2 result = new G2();
            result.deserialize(byteArray.toByteArray());
            return new G2Point(result);
        } catch (RuntimeException exception) {
            throw new DeserializationException(byteArray, exception);
        }
    }

    public static G2Point hashAndMap(String message) {
        return hashAndMap(message.getBytes());
    }

    public static G2Point hashAndMap(byte[] message) {
        G2 result = new G2();
        Mcl.hashAndMapToG2(result, message);
        return new G2Point(result);
    }

    @Override
    public G2Point add(G2Point other) {
        G2 result = new G2();
        Mcl.add(result, this.g2, other.g2);
        return new G2Point(result);
    }

    @Override
    public G2Point times(Scalar scalar) {
        G2 result = new G2();
        Mcl.mul(result, this.g2, scalar.fr);
        return new G2Point(result);
    }

    @Override
    public G2Point negate() {
        G2 result = new G2();
        Mcl.neg(result, this.g2);
        return new G2Point(result);
    }

    public GTElement pair(G1Point other) {
        GT result = new GT();
        Mcl.pairing(result, other.g1, this.g2);
        return new GTElement(result);
    }

    @Override
    public boolean isZero() {
        return this.g2.isZero();
    }

    @Override
    public Pair<FpElement, FpElement> getX() {
        if (this.isZero()) {
            throw new UnsupportedOperationException();
        }
        String[] strArray = this.g2.toString(16).split(" ");
        FpElement x1 = FpElement.of(new BigInteger(strArray[1], 16));
        FpElement x2 = FpElement.of(new BigInteger(strArray[2], 16));
        return new Pair<>(x1, x2);
    }

    @Override
    public Pair<FpElement, FpElement> getY() {
        if (this.isZero()) {
            throw new UnsupportedOperationException();
        }
        String[] strArray = this.g2.toString(16).split(" ");
        FpElement y1 = FpElement.of(new BigInteger(strArray[3], 16));
        FpElement y2 = FpElement.of(new BigInteger(strArray[4], 16));
        return new Pair<>(y1, y2);
    }

    @Override
    public ByteArray serialize() {
        return ByteArray.of(this.g2.serialize());
    }

    @Override
    public String toString() {
        if (this.isZero()) {
            return INFINITY;
        }
        var x = this.getX();
        var y = this.getY();
        return String.format("x0=%s x1=%s y0=%s y1=%s", x.getFirst(), x.getSecond(), y.getFirst(), y.getSecond());
    }

}
