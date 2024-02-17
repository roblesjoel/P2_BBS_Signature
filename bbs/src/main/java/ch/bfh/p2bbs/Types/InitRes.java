package ch.bfh.p2bbs.Types;

import ch.openchvote.util.tuples.Sextuple;

public class InitRes extends Sextuple<G1Point, G1Point, G1Point, G1Point, G1Point, Scalar> {

    public static InitRes INVALID = new InitRes(true);
    private final boolean invalid;

    public InitRes(G1Point abar, G1Point bbar, G1Point d, G1Point t1, G1Point t2, Scalar domain) {
        super(abar, bbar, d, t1, t2, domain);
        invalid = false;
    }

    private InitRes(boolean invalid){
        super(new G1Point(), new G1Point(), new G1Point(), new G1Point(), new G1Point(), new Scalar());
        this.invalid = invalid;
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
        return getFifth();
    }

    public Scalar getDomain() {
        return getSixth();
    }

    public boolean isInvalid(){
        return this.invalid;
    }
}
