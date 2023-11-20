package ch.bfh.evg.group;

public interface MultiplicativeElement<E extends MultiplicativeElement<E, F>, F extends FieldElement<F>> extends GroupElement {

    E multiply(E other);

    E power(F exponent);

    E inverse();

    boolean isOne();

    default E divide(E other) {
        return this.multiply(other.inverse());
    }

}
