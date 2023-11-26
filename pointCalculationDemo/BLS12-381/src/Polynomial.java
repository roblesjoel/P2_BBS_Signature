import java.math.BigInteger;
import java.util.Objects;

public class Polynomial {

    private static final BigInteger P = new BigInteger("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    private final BigInteger coefficient0;
    private final BigInteger coefficient1;

    Polynomial(BigInteger coefficient0, BigInteger coefficient1){
        this.coefficient0 = coefficient0;
        this.coefficient1 = coefficient1;
    }


    public Polynomial negate(){
        BigInteger coefficient0 = this.coefficient0.negate();
        BigInteger coefficient1 = this.coefficient1.negate();

        return new Polynomial(coefficient0, coefficient1);
    }

    public Polynomial add(Polynomial other){
        BigInteger coefficient0 = this.coefficient0.add(other.coefficient0);
        BigInteger coefficient1 = this.coefficient1.add(other.coefficient1);

        return new Polynomial(coefficient0, coefficient1);
    }

    public Polynomial multiply(Polynomial other){

        BigInteger coefficient0 = (this.coefficient0.multiply(other.coefficient0)).add(this.coefficient1.multiply(other.coefficient1).multiply(BigInteger.ONE.negate()));
        BigInteger coefficient1 = this.coefficient0.multiply(other.coefficient1).add(this.coefficient1.multiply(other.coefficient0));

        return new Polynomial(coefficient0, coefficient1);
    }

    public Polynomial multiplyScalar(BigInteger k){
        BigInteger coefficient0 = this.coefficient0.multiply(k);
        BigInteger coefficient1 = this.coefficient1.multiply(k);

        return new Polynomial(coefficient0, coefficient1);
    }

    public Polynomial inverse(){

        BigInteger coefficient0 = this.coefficient0.multiply(BigInteger.ONE.divide(this.coefficient0.pow(2).subtract(this.coefficient1.pow(2).multiply(BigInteger.ONE.negate()))));
        BigInteger coefficient1 = this.coefficient1.negate().multiply(BigInteger.ONE.divide(this.coefficient0.pow(2).subtract(this.coefficient1.pow(2).multiply(BigInteger.ONE.negate()))));

        return new Polynomial(coefficient0, coefficient1);
    }

    //subtraction of 2 polynomials
    public Polynomial subtract(Polynomial other){
        BigInteger coefficient0  = this.coefficient0.add(other.coefficient0.negate());
        BigInteger coefficient1 = this.coefficient1.add(other.coefficient1.negate());

        return new Polynomial(coefficient0, coefficient1);
    }

    public Polynomial divide(Polynomial other){
        BigInteger coefficient0 = this.coefficient0.multiply(other.coefficient0.modInverse(P));
        BigInteger coefficient1 = this.coefficient1.multiply(other.coefficient1.modInverse(P));

        return new Polynomial(coefficient0, coefficient1);
    }

    public Polynomial mod(BigInteger k){
        BigInteger coefficient0 = this.coefficient0.mod(k);
        BigInteger coefficient1 = this.coefficient1.mod(k);

        return new Polynomial(coefficient0, coefficient1);
    }

    //power calculation of polynomials
    public Polynomial pow(Integer k){
        BigInteger coefficient0 = this.coefficient0.pow(k).mod(P);
        BigInteger coefficient1 = this.coefficient1.pow(k).mod(P);

        return new Polynomial(coefficient0, coefficient1);
    }

    @Override
    public String toString() {
        return "Polynomial{" +
                "coefficient0=" + coefficient0 +
                ", coefficient1=" + coefficient1 +
                '}';
    }

    public BigInteger getCoefficient0() {
        return coefficient0;
    }

    public BigInteger getCoefficient1() {
        return coefficient1;
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
