package ch.bfh.p2bbs.Types;

import ch.openchvote.util.tuples.Quadruple;

public class InitRes extends Quadruple<G1Point, G1Point, G1Point, Scalar> {

    public InitRes(G1Point abar, G1Point bbar, G1Point t, Scalar domain) {
        super(abar, bbar, t, domain);
    }

    public G1Point getAbar() {
        return getFirst();
    }

    public G1Point getBbar() {
        return getSecond();
    }

    public G1Point getT() {
        return getThird();
    }

    public Scalar getDomain() {
        return getFourth();
    }
}
