package ch.bfh.evg.proof;

import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.Scalar;
import ch.openchvote.util.sequence.Vector;
import ch.openchvote.util.tuples.Sextuple;

public class Proof extends Sextuple<G1Point, G1Point, Scalar, Scalar, Vector<Scalar>, Scalar> {

    public Proof(G1Point a0, G1Point a1, Scalar s0, Scalar s1, Vector<Scalar> msgCommitments, Scalar sJ1) {
        super(a0, a1, s0, s1, msgCommitments, sJ1);
    }

    public G1Point getA_0() {
        return getFirst();
    }

    public G1Point getA_1() {
        return getSecond();
    }

    public Scalar getS_0() {
        return getThird();
    }

    public Scalar getS_1() {
        return getFourth();
    }

    public Vector<Scalar> getMsg_commitments() {
        return getFifth();
    }

    public Scalar getS_j_1() {
        return getSixth();
    }

    public Object[] toObjectArray(){
        Object[] temp = new Object[5 + getFifth().getLength()];
        temp[0] = getFirst();
        temp[1] = getSecond();
        temp[2] = getThird();
        temp[3] = getFourth();
        for (int i = 1; i <= getFifth().getLength(); i++) {
            temp[i+3] = getFifth().getValue(i);
        }
        temp[temp.length-1] = getSixth();
        return temp;
    }
}
