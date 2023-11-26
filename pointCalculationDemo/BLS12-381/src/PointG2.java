import java.math.BigInteger;
import java.util.Objects;

public class PointG2 {

    private static final BigInteger P = new BigInteger("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    private final Polynomial x;
    private final Polynomial y;

    PointG2(Polynomial x, Polynomial y){
        this.x = x;
        this.y = y;
    }

    boolean isInfinity(){

        return true;
    }


    private static PointG2 add(PointG2 p1){



    return null;
    }

    private static PointG2 doublePoint(){

        return null;
    }

    private static PointG2 scalarMultiply(BigInteger k){

        return null;
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
