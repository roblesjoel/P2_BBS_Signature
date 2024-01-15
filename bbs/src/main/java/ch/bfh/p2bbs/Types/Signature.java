package ch.bfh.p2bbs.Types;

public class Signature {

    public static Signature INVALID = new Signature();

    private final G1Point A;
    private final Scalar e;

    private Signature(){
        this.A = null;
        this.e = null;
    }

    public Signature(G1Point A, Scalar e) {
        this.A = A;
        this.e = e;
    }

    public boolean isInvalid(){
        return A == null || e == null;
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
        return String.format("(%s,%s)", this.A.toString(), this.e.toString());
    }
}
