package ch.bfh.p2bbs.Types;

import ch.bfh.evg.element.ECPoint;
import ch.bfh.evg.element.FpElement;
import ch.bfh.evg.field.Fp;
import ch.openchvote.util.sequence.Vector;

import static ch.bfh.p2bbs.utils.Definitions.*;

public class G1Point extends ECPoint<FpElement, Fp> {
    private final ch.bfh.evg.element.G1Point point;
    public static final G1Point GENERATOR = new G1Point((ECPoint<FpElement, Fp>) G1.getGenerator(), (Fp) G1.getField());
    public static final G1Point ZERO = GENERATOR.subtract(GENERATOR);
    public G1Point(ECPoint<FpElement, Fp> point, Fp field){
        super(field, point.get_X(), point.get_Y(), point.get_Z());
        this.point = (ch.bfh.evg.element.G1Point) point;
    }

    public G1Point(ECPoint<FpElement, Fp> point){
        super((Fp) G1.getField(), point.get_X(), point.get_Y(), point.get_Z());
        this.point = (ch.bfh.evg.element.G1Point) point;
    }

    public G1Point(){
        super(null, null, null, null);
        this.point = null;
    }

    public byte[] serialize(){
        return G1.serialize(point);
    }

    public static G1Point deserialize(byte[] serializedPoint){
        return new G1Point(G1.deserialize(serializedPoint));
    }

    public static G1Point hash_to_curve_g1(byte[] msg, OctetString dst){
        return new G1Point(G1.hashToCurve(msg, dst.toBytes()));
    }

    public G1Point add(G1Point other){
        return new G1Point(G1.add(this.point, other.point), (Fp) G1.getField());
    }

    public G1Point subtract(G1Point other){
        return new G1Point((ECPoint<FpElement, Fp>) G1.subtract(this.point, other.point));
    }

    public G1Point times(Scalar scalar){
        return new G1Point((ECPoint<FpElement, Fp>) G1.times(point, scalar.value));
    }

    public static G1Point sumOfScalarMultiply(Vector<G1Point> points, Vector<Scalar> scalars){
        G1Point res = ZERO;
        for (int i = 1; i <= scalars.getLength(); i++) {
            G1Point scalarMultiplyRes = points.getValue(i).times(scalars.getValue(i));
            res = res.add(scalarMultiplyRes);
        }
        return res;
    }

    public GTElement pair(G2Point other){
        return new GTElement(BLS12381.pair(this.point, other.getPoint()));
    }

    public boolean isZero(){
        return G1.isZero(point);
    }
    @Override
    public String toString(){
        return this.point.toString();
    }

    public boolean isInvalid() {
        return this.point.getFirst() == null || this.point.getSecond() == null || this.point.getThird() == null;
    }
}
