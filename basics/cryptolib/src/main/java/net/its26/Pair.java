package net.its26;

public class Pair<F,L>
{
    public final F first;
    public final L last;

    public Pair(F first, L last)
    {
        assert(first != null);
        assert(last != null);
        this.first = first;
        this.last = last;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }

        boolean ret = false;

        if (other instanceof Pair)
        {
            Pair o = (Pair)other;
            ret = (o.first.equals(first)) && (o.last.equals(last));
        }

        return ret;
    }

    @Override
    public int hashCode()
    {
        return first.hashCode() + last.hashCode();
    }
}
