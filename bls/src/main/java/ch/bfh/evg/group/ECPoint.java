package ch.bfh.evg.group;

import ch.bfh.evg.jni.JNI;

public abstract class ECPoint<E extends ECPoint<E, F, G>, F extends FieldElement<F>, G> extends JNI implements AdditiveElement<E, F> {

    public static final String INFINITY = "INFINITY";

    public abstract G getX();

    public abstract G getY();

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || this.getClass() != obj.getClass()) return false;
        var other = (GroupElement) obj;
        return this.serialize().equals(other.serialize());
    }

    @Override
    public int hashCode() {
        return this.serialize().hashCode();
    }

}
