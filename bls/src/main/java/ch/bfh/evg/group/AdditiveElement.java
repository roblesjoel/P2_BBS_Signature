package ch.bfh.evg.group;

public interface AdditiveElement<E extends AdditiveElement<E, F>, F extends FieldElement<F>> extends GroupElement {

    E add(E other);

    E times(F scalar);

    E negate();

    boolean isZero();

    default E subtract(E other) {
        return this.add(other.negate());
    }

}
