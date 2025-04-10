package net.its26;

import java.math.BigInteger;

public class EC 
{

    public static class Point
    {
        public static Point INF = new Point(BigInteger.ZERO, BigInteger.ZERO);

        public final BigInteger x;
        public final BigInteger y;

        public Point(BigInteger x, BigInteger y)
        {
            this.x = x;
            this.y = y;
        }

        @Override
        public boolean equals(Object other)
        {
            if (!(other instanceof Point))
            {
                return false;
            }

            Point o = (Point)other;

            return o.x.equals(x) && o.y.equals(y);
        }

        @Override
        public int hashCode()
        {
            return x.hashCode() ^ y.hashCode();
        }

        @Override
        public String toString()
        {
            if (this.equals(INF))
            {
                return "INF";
            }
            else
            {
                return x.toString() + ":" + y.toString(0);
            }
        }
    }

    // multiply P by a scalar n > 0 in GF m
    public static Point multiply(Point p, BigInteger n, BigInteger m, int a, int b)
    {
        assert(n.compareTo(BigInteger.ZERO) >= 0);

        if (n.equals(BigInteger.ZERO))
        {
            return Point.INF;
        }
        
        while (!Common.isOdd(n))
        {
            p = timesTwo(p, m, a);
            n = n.shiftRight(1);
        }
    
        Point ret = p;

        while (n.compareTo(BigInteger.ZERO) > 0)
        {
            n = n.shiftRight(1);
            p = timesTwo(p, m, a);
    
            if (Common.isOdd(n))
            {
                ret = add(p, ret, m);
            }
        }

        return ret;
    }

    // Slides "Einfuehrung in die Kryptographie WS2024_v0.1, p135"
    public static Point add(Point p, Point q, BigInteger m)
    {
        // INF handling
        if (p.equals(Point.INF))
        {
            return q;
        }

        if (q.equals(Point.INF))
        {
            return p;
        }

        if (p.x.equals(q.x))
        {
            return Point.INF;
        }

        BigInteger tmpDenom = q.x.subtract(p.x).mod(m);
        assert(tmpDenom.compareTo(BigInteger.ZERO) >= 0);
        BigInteger tmpDenomInv = Common.getInverse(tmpDenom, m);
        BigInteger tmpNum = q.y.subtract(p.y).mod(m);
        assert(tmpNum.compareTo(BigInteger.ZERO) >= 0);

        // tmp := (y2 - y1) / (x2 - x1)
        BigInteger tmp = tmpNum.multiply(tmpDenomInv);

        BigInteger x = tmp.multiply(tmp).subtract(p.x).subtract(q.x).mod(m);
        assert(x.compareTo(BigInteger.ZERO) >= 0);

        BigInteger tmp2 = p.x.subtract(x).mod(m);
        assert(tmp2.compareTo(BigInteger.ZERO) >= 0);
        BigInteger y = tmp.multiply(tmp2).subtract(p.y).mod(m);
        assert(y.compareTo(BigInteger.ZERO) >= 0);

        return new Point(x, y);
    }

    // Slides "Einfuehrung in die Kryptographie WS2024_v0.1, p136"
    public static Point timesTwo(Point p, BigInteger m, int a)
    {
        // INF handling
        if (p.equals(Point.INF))
        {
            return p;
        }

        // 2 * y1
        BigInteger tmpDenom = p.y.multiply(BigInteger.TWO).mod(m);
        assert(tmpDenom.compareTo(BigInteger.ZERO) >= 0);
        // 1 / (2 * y1)
        BigInteger tmpDenomInv = Common.getInverse(tmpDenom, m);

        // 3*x1^2 + a
        BigInteger tmpNum = p.x.multiply(p.x).multiply(BigInteger.valueOf(3)).add(BigInteger.valueOf(a)).mod(m);
        assert(tmpNum.compareTo(BigInteger.ZERO) >= 0);
        
        // (3*x1^2 + a) / (2 * y1)
        BigInteger tmp = tmpNum.multiply(tmpDenomInv).mod(m);

        // ((3*x1^2 + a) / (2 * y1))^2 - 2*x1
        BigInteger x = tmp.multiply(tmp).subtract(p.x.multiply(BigInteger.TWO)).mod(m);

        BigInteger tmp2 = p.x.subtract(x).mod(m);
        assert(tmp2.compareTo(BigInteger.ZERO) >= 0);

        BigInteger y = tmp.multiply(tmp2).subtract(p.y).mod(m);
        assert(y.compareTo(BigInteger.ZERO) >= 0);
        
        return new Point(x, y);
    }



}
