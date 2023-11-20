package ch.bfh.evg.bls12_381;

import ch.bfh.evg.group.MultiplicativeElement;
import ch.bfh.evg.jni.JNI;
import ch.openchvote.util.sequence.ByteArray;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class GTElement extends JNI implements MultiplicativeElement<GTElement, FrElement> {

    public static final GTElement GENERATOR = G1Point.GENERATOR.pair(G2Point.GENERATOR);
    public static final GTElement ONE = GENERATOR.divide(GENERATOR);
    public static final int BYTE_LENGTH = 12 * 48;

    private final GT gt;

    // package privacy
    GTElement(GT gt) {
        this.gt = gt;
    }

    public static GTElement getRandom() {
        return GENERATOR.power(FrElement.getRandom());
    }

    public static GTElement deserialize(ByteArray byteArray) throws DeserializationException {
        try {
            GT gt = new GT();
            gt.deserialize(byteArray.toByteArray());
            return new GTElement(gt);
        } catch (RuntimeException exception) {
            throw new DeserializationException(byteArray, exception);
        }
    }

    @Override
    public GTElement multiply(GTElement other) {
        GT result = new GT();
        Mcl.mul(result, this.gt, other.gt);
        return new GTElement(result);
    }

    @Override
    public GTElement power(FrElement exponent) {
        GT result = new GT();
        Mcl.pow(result, this.gt, exponent.fr);
        return new GTElement(result);
    }

    @Override
    public GTElement inverse() {
        GT result = new GT();
        Mcl.inv(result, this.gt);
        return new GTElement(result);
    }

    @Override
    public boolean isOne() {
        return this.gt.isOne();
    }

    public FpElement getCoefficient(int i) {
        if (i < 0 || i >=12) {
            throw new IllegalArgumentException();
        }
        return FpElement.of(new BigInteger(this.gt.toString(16).split(" ")[i], 16));
    }

    @Override
    public String toString() {
        return IntStream.range(0, 12).mapToObj(this::getCoefficient).map(FpElement::toString).collect(Collectors.joining(" "));
    }

    @Override
    public ByteArray serialize() {
        return ByteArray.of(this.gt.serialize());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || this.getClass() != obj.getClass()) return false;
        var other = (GTElement) obj;
        return this.serialize().equals(other.serialize());
    }

    @Override
    public int hashCode() {
        return this.serialize().hashCode();
    }

}
