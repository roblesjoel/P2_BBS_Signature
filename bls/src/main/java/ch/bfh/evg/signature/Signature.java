package ch.bfh.evg.signature;

import ch.bfh.evg.bls12_381.G1Point;
import ch.bfh.evg.bls12_381.Scalar;

public class Signature {

    private final G1Point A;
    private final Scalar e;

    public Signature(G1Point A, Scalar e) {
        this.A = A;
        this.e = e;
    }

    public G1Point getPoint(){
        return A;
    }

    public Scalar getScalar(){
        return e;
    }

    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || this.getClass() != object.getClass()) return false;

        Signature other = (Signature) object;

        if (!this.A.equals(other.A)) return false;
        return this.e.equals(other.e);
    }

    public String toString() {
        return String.format("(%s,%s,%s)", this.A.toString(), this.e.toString());
    }
}
