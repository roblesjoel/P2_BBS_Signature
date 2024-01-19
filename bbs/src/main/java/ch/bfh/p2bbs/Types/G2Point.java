package ch.bfh.p2bbs.Types;

import ch.bfh.hnr1.element.ECPoint;
import ch.bfh.hnr1.element.Fp2Element;
import ch.bfh.hnr1.element.FpElement;
import ch.bfh.hnr1.field.Fp;
import ch.bfh.hnr1.field.Fp2;

import static ch.bfh.p2bbs.utils.Definitions.G1;
import static ch.bfh.p2bbs.utils.Definitions.G2;

public class G2Point extends ECPoint<Fp2Element, Fp2> {

    private final ch.bfh.hnr1.element.G2Point point;
    public static final G2Point GENERATOR = new G2Point((ECPoint<Fp2Element, Fp2>) G2.getGenerator(), (Fp2) G2.getField());

    public G2Point(ECPoint<Fp2Element, Fp2> point, Fp2 field){
        super(field, point.get_X(), point.get_Y(), point.get_Z());
        this.point = (ch.bfh.hnr1.element.G2Point) point;
    }

    private G2Point(ECPoint<Fp2Element, Fp2> point){
        super((Fp2) G2.getField(), point.get_X(), point.get_Y(), point.get_Z());
        this.point = (ch.bfh.hnr1.element.G2Point) point;
    }

    public ch.bfh.hnr1.element.G2Point getPoint(){
        return point;
    }

    public byte[] serialize(){
        return G2.serialize(this.point);
    }

    public static G2Point deserialize(byte[] serializedPoint){
        var temp = G2.deserialize(serializedPoint);
        return new G2Point(temp);
    }

    public static G2Point hash_to_curve_g2(byte[] msg){
        return new G2Point(G2.hashToCurve(msg));
    }

    public G2Point times(Scalar scalar){
        return new G2Point((ECPoint<Fp2Element, Fp2>) G2.times(point, scalar.value));
    }

    public G2Point add(G2Point other){
        return new G2Point(G2.add(this.point, other.point));
    }

    public G2Point negate(){
        return new G2Point(G2.negate(this.point));
    }

    @Override
    public String toString(){
        return this.point.toString();
    }

    public boolean isInvalid(){
        return this.point == null;
    }
}
