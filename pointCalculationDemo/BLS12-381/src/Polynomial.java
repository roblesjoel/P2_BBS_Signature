import java.math.BigInteger;
import java.util.Objects;

public class Polynomial {

    private final BigInteger coefficient0;
    private final BigInteger coefficient1;

    Polynomial(BigInteger coefficient0, BigInteger coefficient1){
        this.coefficient0 = coefficient0;
        this.coefficient1 = coefficient1;
    }




    private Polynomial add(Polynomial other){
        BigInteger coefficient0 = this.coefficient0.add(other.coefficient0);
        BigInteger coefficient1 = this.coefficient1.add(other.coefficient1);

        return new Polynomial(coefficient0, coefficient1);
    }

    private Polynomial multiply(Polynomial other){

        BigInteger coefficient0 = (this.coefficient0.multiply(other.coefficient0)).add(this.coefficient1.multiply(other.coefficient1).multiply(BigInteger.ONE.negate()));
        BigInteger coefficient1 = this.coefficient0.multiply(other.coefficient1).add(this.coefficient1.multiply(other.coefficient0));

        return new Polynomial(coefficient0, coefficient1);
    }

    private Polynomial inverse(){

        BigInteger coefficient0 = this.coefficient0.multiply(BigInteger.ONE.divide(this.coefficient0.pow(2).subtract(this.coefficient1.pow(2).multiply(BigInteger.ONE.negate()))));
        BigInteger coefficient1 = this.coefficient1.negate().multiply(BigInteger.ONE.divide(this.coefficient0.pow(2).subtract(this.coefficient1.pow(2).multiply(BigInteger.ONE.negate()))));

        return new Polynomial(coefficient0, coefficient1);
    }

    @Override
    public String toString() {
        return "Polynomial{" +
                "coefficient0=" + coefficient0 +
                ", coefficient1=" + coefficient1 +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Polynomial that = (Polynomial) o;
        return Objects.equals(coefficient0, that.coefficient0) && Objects.equals(coefficient1, that.coefficient1);
    }

    @Override
    public int hashCode() {
        return Objects.hash(coefficient0, coefficient1);
    }
}
