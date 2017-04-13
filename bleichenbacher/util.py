from Crypto.Util.number import *

def get_best_from_existing(s2, best_lower, n):
        for t1 in range(2, 3000):
            u1 = s2 * t1 % n
            t1_inv = inverse(t1, n)
            if s2 % n != u1 * t1_inv % n:
                sys.exit("asfdsd")
            #se za t1 > u1 oz obratno kej jst vem
            if u1 < (3*t1)//2:
                fraction_val = best_lower[0]/best_lower[1]
                tmp_fraction_val = u1/t1
                if tmp_fraction_val < fraction_val:
                    print("%s, %s" % (u1, t1))
                    best_lower = [u1, t1]
        return best_lower
    
def divide_ceil(a, b): 
    r = a // b
    if r * b == a:
        return r
    else:
        return r+1
    
def get_rs(si, a, b, n, mmin, mmax):
    """ Get all r for which [si * a, si * b] intersects [r * n + 2*B, r * n + 3*B - 1]
    """
    r_min = si*a//n
    r_max = si*b//n
    if si * a >= r_min * n + mmax:
        r_min += 1
    if si * b < r_max * n + mmin:
        r_max -= 1
    return range(r_min, r_max+1)

def get_new_bounds(si, r, n, mmin, mmax):
    new_a = (r*n + mmin)//si
    if new_a * si < r*n + mmin:
        new_a += 1
    new_b = (r*n + mmax)//si
    return new_a, new_b

def get_candidate_bounds(si, a, b, mmin, mmax, n):
    """
    The si is known, now calculate bounds for each candidate r.
    """
    rs = get_rs(si, a, b, n, mmin, mmax)
    #print "rs: %s" % rs
    candidate_bounds = []
    for cand_r in rs:
        na, nb = get_new_bounds(si, cand_r, n, mmin, mmax) #todo: lcm
        m1 = max(na, mmin) 
        m2 = min (nb, mmax)
        if m1 <= m2:
            candidate_bounds.append([m1, m2])
    return candidate_bounds
 
def get_intersect_rs(oracle, n, B, num, min_r, max_r):
    """
    Returns pairs (r,s) for which r*n + oracle.mmin < s*num < r*n + oracle.mmax
    """
    s_cands1 = []
    for r in range(min_r, max_r):
        s1 = (r*n + oracle.mmax) // num
        s2 = s1 + 1
        s_candidates = [s1, s2]
        for s in s_candidates:
            intersects = does_intersect_I(oracle, n, r, s, num, num)
            if intersects:
                s_cands1.append((r, s))
    return s_cands1

def does_intersect_I(oracle, n, r, s, a, b):
    if (s*a > r*n + oracle.mmin and s*a < r*n + oracle.mmax) or \
        (s*b > r*n + oracle.mmin and s*b < r*n + oracle.mmax):
        return True
    else:
        return False

def get_dividors(num, max):
    dividors = []
    for i in range(2, max):
        if num % i == 0:
            dividors.append(i)
    return dividors
    
def letsee(oracle, n, B, num, min_r, max_r):
    rl = []
    for r in range(min_r, max_r):
        s = r * n // num
        t1 = (r*n - s*num) / B
        t2 = ((s+1)*num - r*n) / B
        rl.append([r, t1, t2])
    return rl
        
 