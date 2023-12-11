import java.math.BigInteger;
import java.util.Objects;

public class Polynomial {

    /**
     *
     */
    private static final BigInteger P = new BigInteger("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    private final BigInteger coefficient0;
    private final BigInteger coefficient1;

    /**
     * constructor of Polynomial
     * @param coefficient0
     * @param coefficient1
     */
    Polynomial(BigInteger coefficient0, BigInteger coefficient1){
        this.coefficient0 = coefficient0;
        this.coefficient1 = coefficient1;
    }

    /**
     * negate operation of a polynom
     * @return a polynomial
     */
    public Polynomial negate(){
        BigInteger coefficient0 = this.coefficient0.negate().mod(P);
        BigInteger coefficient1 = this.coefficient1.negate().mod(P);

        return new Polynomial(coefficient0, coefficient1);
    }

    /**
     * add operation for polynomials
     * @param other second operand
     * @return polynomial of two added polynomial
     */
    public Polynomial add(Polynomial other){
        BigInteger coefficient0 = this.coefficient0.add(other.coefficient0).mod(P);
        BigInteger coefficient1 = this.coefficient1.add(other.coefficient1).mod(P);

        return new Polynomial(coefficient0, coefficient1);
    }

    /**
     * multiplication operation for polynomials
     * @param other second operand
     * @return result of the multiplication operation with polynomials
     */
    public Polynomial multiply(Polynomial other){

        BigInteger coefficient0 = (this.coefficient0.multiply(other.coefficient0)).add(this.coefficient1.multiply(other.coefficient1).multiply(BigInteger.ONE.negate())).mod(P);
        BigInteger coefficient1 = this.coefficient0.multiply(other.coefficient1).add(this.coefficient1.multiply(other.coefficient0)).mod(P);

        return new Polynomial(coefficient0, coefficient1);
    }

    /**
     * multiplication from a polynomial with a scalar
     * @param k scalar to multiplicate the polynomial with
     * @return result of the operation
     */
    public Polynomial multiplyScalar(BigInteger k){
        BigInteger coefficient0 = this.coefficient0.multiply(k).mod(P);
        BigInteger coefficient1 = this.coefficient1.multiply(k).mod(P);

        return new Polynomial(coefficient0, coefficient1);
    }

    /**
     * inverse operation of a polynomial
     * @return inverse of polynomial
     */
    public Polynomial inverse(){

        BigInteger temp = this.coefficient0.pow(2).subtract(BigInteger.ONE.negate().multiply(this.coefficient1.pow(2)));

        BigInteger coefficient0 = this.coefficient0.multiply(temp).modInverse(P);
        BigInteger coefficient1 = this.coefficient1.negate().multiply(temp).modInverse(P);

        return new Polynomial(coefficient0, coefficient1);
    }

    /**
     * square operation of polynomial
     * @return squared polynomial
     */
    public Polynomial square(){
        return this.multiply(this);
    }

    /**
     * pow operation for a polynomial with square and multiply algorithm
     * @param k scalar you
     * @return result of operation
     */
    public Polynomial pow(BigInteger k){

        Polynomial result = new Polynomial(BigInteger.ONE, BigInteger.ONE);
        Polynomial base = this;

        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.mod(BigInteger.TWO).equals(BigInteger.ONE)) { // Check if k is odd
                result = result.multiply(base);
            }
            base = base.square();
            k = k.divide(BigInteger.TWO);
        }

        return result;
    }


    /**
     * toString method for making the polynomial readable
     * @return
     */
    @Override
    public String toString() {
        return "Polynomial{" +
                "coefficient0=" + coefficient0 +
                ", coefficient1=" + coefficient1 +
                '}';
    }

    /**
     * getter method for getting coefficient0
     * @return coefficient0 of the polynomial
     */
    public BigInteger getCoefficient0() {
        return this.coefficient0;
    }

    /**
     * getter method for getting coefficient1
     * @return coefficient1 of the polynomial
     */
    public BigInteger getCoefficient1() {
        return this.coefficient1;
    }

    /**
     *
     * @param o
     * @return
     */
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
