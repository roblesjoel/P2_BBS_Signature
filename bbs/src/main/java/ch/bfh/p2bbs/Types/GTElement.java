package ch.bfh.p2bbs.Types;

import ch.bfh.hnr1.element.Fp12Element;

import static ch.bfh.p2bbs.utils.Definitions.GT;

public class GTElement {

    public static final GTElement GENERATOR = new GTElement(GT.getGenerator());
    public static final GTElement ONE = GENERATOR.divide(GENERATOR);

    private final Fp12Element point;

    public GTElement(Fp12Element newPoint){
        this.point = newPoint;
    }

    public GTElement divide(GTElement other){
        return new GTElement(GT.divide(this.point, other.point));
    }

    public GTElement multiply(GTElement other){
        return new GTElement(GT.multiply(this.point, other.point));
    }

    public boolean equals(GTElement other) {
        return this.point.getFirst().equals(other.point.getFirst()) && this.point.getSecond().equals(other.point.getSecond());
    }
}
