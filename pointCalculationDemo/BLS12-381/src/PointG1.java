import java.math.BigInteger;
import java.util.Objects;

public class PointG1 {

    private static final BigInteger P = new BigInteger("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    private final BigInteger x;
    private final BigInteger y;

    //constructor
    public PointG1(BigInteger x, BigInteger y){
        this.x = x;
        this.y = y;
    }

    //check if point is in infinity
    public boolean isInfinity(){
        return this.x == null && this.y == null;
    }

    //calculation of the inverse of the point
    PointG1 inverse() {
        return new PointG1(this.x, this.y.negate().mod(P));
    }

    //Elliptic curve operation for adding two points
    public PointG1 add(PointG1 other){
        if(this.isInfinity())
            return other;
        if(other.isInfinity())
            return this;

        if(this.x.equals(other.x)){
            if(this.y.equals(other.y.negate().mod(P))){
                return new PointG1(null, null);
            }else{
                return doublePoint();
            }
        }

        BigInteger slope = other.y.subtract(this.y).multiply(other.x.subtract(this.x).modInverse(P)).mod(P);
        BigInteger x3 = slope.pow(2).subtract(this.x).subtract(other.x).mod(P);
        BigInteger y3 = slope.multiply(this.x.subtract(x3)).subtract(this.y).mod(P);

        return new PointG1(x3,y3);

    }

    //doubling a point/ adding the point to itself
    public PointG1 doublePoint() {

        BigInteger slope = this.x.pow(2).multiply(BigInteger.valueOf(3)).multiply(this.y.multiply(BigInteger.valueOf(2)).modInverse(P)).mod(P);
        BigInteger x3 = slope.pow(2).subtract(this.x.multiply(BigInteger.valueOf(2))).mod(P);
        BigInteger y3 = slope.multiply(this.x.subtract(x3)).subtract(this.y).mod(P);

        return new PointG1(x3, y3);
    }

    //square and muliply algorithm for multiplication of a point with a scalar
    public PointG1 scalarMultiply(BigInteger k){
        PointG1 result = new PointG1(null, null);
        PointG1 addend = this;

        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.mod(BigInteger.TWO).equals(BigInteger.ONE)) { // Check if k is odd
                result = result.add(addend);
            }
            addend = addend.doublePoint();
            k = k.divide(BigInteger.TWO);
        }

        return result;
    }


    //toString method for nice output
    public String toString(){
        return "x: " + this.x + " y: " + this.y;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PointG1 pointG1 = (PointG1) o;
        return Objects.equals(x, pointG1.x) && Objects.equals(y, pointG1.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }
}
