package ch.bfh.p2bbs.Types;

import ch.openchvote.util.tuples.Quadruple;
import ch.openchvote.util.tuples.Septuple;
import ch.openchvote.util.tuples.Sextuple;

public class InitRes extends Sextuple<G1Point, G1Point, G1Point, G1Point, G1Point, Scalar> {

    public static InitRes INVALID = new InitRes();

    public InitRes(G1Point abar, G1Point bbar, G1Point d, G1Point t1, G1Point t2, Scalar domain) {
        super(abar, bbar, d, t1, t2, domain);
    }

    private InitRes(){
        super(null, null, null, null, null, null);
    }

    public G1Point getAbar() {
        return getFirst();
    }

    public G1Point getBbar() {
        return getSecond();
    }

    public G1Point getD() {
        return getThird();
    }

    public G1Point getT1() {
        return getFourth();
    }

    public G1Point getT2() {
        return getFirst();
    }

    public Scalar getDomain() {
        return getSixth();
    }

    public boolean isInvalid(){
        return getAbar() == null || getBbar() == null || getD() == null || getT1() == null || getT2() == null || getDomain() == null;
    }
}
