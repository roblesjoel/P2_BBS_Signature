import java.math.BigInteger;
import java.util.Objects;


public class PointG2 {

    private static final BigInteger P = new BigInteger("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    private final Polynomial x;
    private final Polynomial y;

    //constructor
    public PointG2(Polynomial x, Polynomial y){
        this.x = x;
        this.y = y;
    }

    //check if point is infinity
    public boolean isInfinity(){

        return this.x == null && this.y == null;
    }


    //addition of two points in G2
    public PointG2 add(PointG2 other){
        if(this.isInfinity()) return other;
        if(other.isInfinity()) return this;

        if(this.x.equals(other.x)){
            if(this.y.equals(other.y.negate())){
                return new PointG2(null, null);
            }else{
                return doublePoint();
            }
        }

        Polynomial slope = other.y.add(this.y.negate()).multiply(other.x.add(this.x.negate()).inverse());
        Polynomial x3 = slope.square().add(this.x.negate()).add(other.x.negate());
        Polynomial y3 = slope.multiply(this.x.add(x3.negate())).add(this.y.negate());

        return new PointG2(x3, y3);
    }

    public PointG2 doublePoint(){

        Polynomial slope = this.x.square().multiplyScalar(BigInteger.valueOf(3)).multiply(this.y.multiplyScalar(BigInteger.valueOf(2)).inverse());
        Polynomial x3 = slope.square().add(this.x.multiplyScalar(BigInteger.valueOf(2)).negate());
        Polynomial y3 = slope.multiply(this.x.add(x3.negate())).add(this.y.negate());

        return new PointG2(x3, y3);
    }

    public PointG2 scalarMultiply(BigInteger k){
        PointG2 result = new PointG2(null, null);
        PointG2 addend = this;

        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.mod(BigInteger.TWO).equals(BigInteger.ONE)) { // Check if k is odd
                result = result.add(addend);
            }
            addend = addend.doublePoint();
            k = k.divide(BigInteger.TWO);
        }

        return result;
    }


    @Override
    public String toString() {
        return "PointG2{" +
                "x=" + x +
                ", y=" + y +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PointG2 pointG2 = (PointG2) o;
        return Objects.equals(x, pointG2.x) && Objects.equals(y, pointG2.y);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y);
    }
}
