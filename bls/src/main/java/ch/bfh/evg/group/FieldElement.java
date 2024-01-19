package ch.bfh.evg.group;

import java.math.BigInteger;

public abstract class FieldElement<F extends FieldElement<F>> implements AdditiveElement<F, F>, MultiplicativeElement<F, F> {

    protected abstract BigInteger toBigInteger();

    @Override
    public F times(F scalar) {
        return this.multiply(scalar);
    }

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
