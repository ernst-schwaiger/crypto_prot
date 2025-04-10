package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ECTest 
{
    @Test void ecMultiply()
    {
        // test curve y^2 = x^3 - x + 4
        int a = - 1;
        int b = 4;
        BigInteger m = BigInteger.valueOf(43);

        // test GF 43
        EC.Point p1 = new EC.Point(BigInteger.ONE, BigInteger.valueOf(41));
        List<EC.Point> points = new ArrayList<>();
        points.add(p1);
        
        BigInteger i = BigInteger.TWO;

        while(true)
        {
            EC.Point pNew = EC.multiply(p1, i, m, a, b);
            if (!points.contains(pNew))
            {
                points.add(pNew);
                i = i.add(BigInteger.ONE);
            }
            else
            {
                break;
            }
        }

        assertTrue(points.size() >= 2);

        // INF Point multiplication always returns INF
        assertTrue(EC.multiply(EC.Point.INF, BigInteger.ZERO, m, a, b).equals(EC.Point.INF));
        assertTrue(EC.multiply(EC.Point.INF, BigInteger.ONE, m, a, b).equals(EC.Point.INF));
        assertTrue(EC.multiply(EC.Point.INF, BigInteger.TWO, m, a, b).equals(EC.Point.INF));

        for (EC.Point point : points)
        {
            // Point must adhere to the curve equation, except for INF
            if (!point.equals(EC.Point.INF))
            {
                BigInteger y_squared = point.y.multiply(point.y).mod(m);
                // x^3 + ax + b
                BigInteger curveVal = point.x.multiply(point.x).multiply(point.x).add(point.x.multiply(BigInteger.valueOf(a))).add(BigInteger.valueOf(b)).mod(m);
                assertTrue (y_squared.equals(curveVal));    
            }

            assertTrue(EC.multiply(p1, BigInteger.ZERO, m, a, b).equals(EC.Point.INF));
        }

        // Symmetry of addition
        for (int j = 0; j < points.size(); j++)
        {
            EC.Point p_j = points.get(j);

            for (int k = j + 1; k < points.size(); k++)
            {
                EC.Point p_k = points.get(k);

                EC.Point sum1 = EC.add(p_j, p_k, m);
                EC.Point sum2 = EC.add(p_k, p_j, m);

                assertTrue(sum1.equals(sum2));
            }
        }
    }
}
