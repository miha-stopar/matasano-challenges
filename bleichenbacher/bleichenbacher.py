import Crypto
from Crypto.Util.number import *
from Crypto.Util.py3compat import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from trimmer import Trimmer
from modtrimmer import ModTrimmer
from oracle import Oracle
from util import *

def pad(m, key):
    randFunc = key._randfunc
    modBits = Crypto.Util.number.size(key.n)
    k = ceil_div(modBits, 8) # Convert from bits to bytes (length of n in bytes)
    mLen = len(m)
    if mLen > k-11:
        raise ValueError("Plaintext is too long.")
    class nonZeroRandByte:
        def __init__(self, rf): self.rf=rf
        def __call__(self, c):
            while bord(c)==0x00: c=self.rf(1)[0]
            return c
    r = map(nonZeroRandByte(randFunc), randFunc(k-mLen-3))
    ps = tobytes(r)
    em = b('\x00\x02') + ps + bchr(0x00) + b(m)
    return em

class RSA1():
    def __init__(self, n, e, d):
        self.key = RSA.construct((n, e, d))
        self.n = n
        self.e = e
        self.d = d
        modBits = Crypto.Util.number.size(n)
        self.k = ceil_div(modBits, 8) # Convert from bits to bytes (length of n in bytes)

    def encrypt(self, m):
        em = pad(m, self.key)
        #l = bytes_to_long(em)
        l = int.from_bytes(em, byteorder='big')
        if config["with_encryption"]:
            encrypted = pow(l, self.e, self.n) # RSA.encrypt is not used due to problems with long_to_bytes
            return encrypted 
        else:
            # only padding if with_encryption = False
            return l

    def decrypt(self, c, mmin, mmax):
        m = None
        if config["with_encryption"]:
            decrypted = pow(c, self.d, self.n)
            #m = long_to_bytes(decrypted, 8) # without 8 it does not return a proper inverse (first byte is missing)
            m = c.to_bytes(c.bit_length()//8 + 1, byteorder='big')
            em = m
        else:
            decrypted = c
            #m = long_to_bytes(c, 8) # without 8 it does not return a proper inverse (first byte is missing)
            m = c.to_bytes(c.bit_length()//8 + 1, byteorder='big')
            em = bchr(0x00)*(self.k-len(m)) + m
        #sep = em.find(bchr(0x00),2)
        #if not em.startswith(b('\x00\x02')) or sep<10:
        #if em.startswith(b('\x00\x02')): # not enough, this could be for example smaller than mmin
        if decrypted > mmin and decrypted < mmax:
            conformant = True
        else:
            conformant = False
        #return em[sep+1:], conformant
        return em, conformant

def get_conformant_optimized_si(oracle, start_r, c, a, b, rsa, n, B, e, unsuccessful_rs):
    """
    Try first values for si for which the intersection with the conformant interval is the largest,
    however, the improvement is minimal or none
    """
    oracle_queries = 0
    r = start_r
    r_offset = 2

    while True:
        min_r = r
        max_r = r + r_offset
        candidates = {}
        
        for tmp_r in range(min_r, max_r + 1):
            min_si = 1 + (tmp_r*n + oracle.mmin) // b
            max_si = (tmp_r*n + oracle.mmax) // a
            for si in range(min_si, max_si+1):
                intersection_min = max(tmp_r*n + oracle.mmin, si*a)
                intersection_max = min(tmp_r*n + oracle.mmax, si*b)
                inters = (intersection_max - intersection_min) / (si*b - si*a)
                candidates[si] = [tmp_r, inters]
        sorted_candidates = sorted(candidates.items(), key=lambda x:x[1][1], reverse=True)

        for cand in sorted_candidates:
            si = cand[0]
            if config["with_encryption"]:
                new_c = (c * pow(si, e, n)) % n
            else:
                new_c = (c * si) % n
            conformant = oracle.call(new_c)
            oracle_queries += 1
            if conformant:
                #print("=========")
                return si, r, oracle_queries
            else:
                unsuccessful_rs.append(cand[1][0])
        r += r_offset + 1

def get_conformant(oracle, start_r, c, a, b, rsa, n, B, e, check_only_one_r = False):
    """
    Start searching from (start_r * n on) for s for which s*m is conformant
    """
    oracle_queries = 0
    r = start_r

    while True:
        s_cands = get_s_candidates(oracle, n, r, a, b, None, None)
        for si in s_cands:
            if config["with_encryption"]:
                new_c = (c * pow(si, e, n)) % n
            else:
                new_c = (c * si) % n
            conformant = oracle.call(new_c, p=c)
            
            #if conformant:
            #    best_lower = get_best_from_existing(si, [1, 1], n)
            #    if best_lower != [1, 1]:
            #        print(best_lower)
            
            oracle_queries += 1
            #print(si*(b-a)/B)
            if conformant:
                #print("=========")
                return si, r, oracle_queries
            else:
                #print("--------")
                pass
        if check_only_one_r:
            return None, start_r, oracle_queries
        r += 1
           
def get_intersection_with_I_length(oracle, n, r, s, a, b):
    intersection_min = max(r*n + oracle.mmin, s*a)
    intersection_max = min(r*n + oracle.mmax, s*b)
    if intersection_max < intersection_min:
        return 0
    else:
        return intersection_max - intersection_min
    
def get_s_candidates(oracle, n, r, a, b, fa, fb, out=False):
    min_si = 1 + (r*n + oracle.mmin) // b
    max_si = (r*n + oracle.mmax) // a
    
    s_candidates = range(min_si, max_si+1)
    s_cands1 = list(s_candidates)
           
    if fa == None:
        return s_cands1

    s_cands2 = []
    for s in s_cands1:
        # check if conflicts:
        rs = get_rs(s, fa, fb, n, oracle.mmin, oracle.mmax)
        if len(rs) == 0:
            s_cands2.append(s)
    if out:
        print(s_candidates)
        print(s_cands1)

    return s_cands2

def get_s_for_number(oracle, n, B, num, fa, fb, max_attempts=1000, out=False):
    # and not for the interval
    r = 1
    #r = B * num / n
    i = 0
    while True:
        if i == max_attempts:
            return None, None
        i += 1
        s_cands = get_s_candidates(oracle, n, r, num, num, fa, fb, out)
        if len(s_cands) > 0:
            s = s_cands[0]
            return r, s 
        else:
            r += 1
            
def find_best_s(oracle, a, b, n, B, length_of_multiplied_interval, length_should_not_exceed, \
                fa, fb, max_attempts=1000):
    s = length_of_multiplied_interval // (b - a)
    anchor_r = s * a // n
    candidates = {}
    #for r in range(anchor_r - 3, anchor_r + 10):
    r = max(1, anchor_r - 3)
    biggest_inters = 0
    attempts = 0
    while True:
        r += 1
        
        attempts += 1
        if attempts == max_attempts:
            return None, None
        
        if r > anchor_r + 100 and len(candidates) > 0:
            break
        s_cands2 = get_s_candidates(oracle, n, r, a, b, fa, fb)
        if len(s_cands2) == 0:
            continue
        
        max_len = 0
        max_len_index = None
        for ind, s in enumerate(s_cands2):
            l = get_intersection_with_I_length(oracle, n, r, s, a, b)
            if l > max_len:
                max_len = l
                max_len_index = ind
        if max_len == 0:
            print("hmm")
            continue
        s = s_cands2[max_len_index]
        
        overflows_only_one_side = (s*a > r*n + oracle.mmin) or (s*b < r*n + oracle.mmax)
        if biggest_inters > 0.5 and r > anchor_r + 10:
            break
        if s*b - s*a > length_should_not_exceed and not overflows_only_one_side:
            continue
        candidates[s] = [r, max_len / B]
        bla = max_len / B
        if bla > biggest_inters:
            biggest_inters = bla
    if len(candidates) == 0:
        print("hmmmmmmmmmmmmmmmmmmmm")
        sys.exit(1)
    sorted_candidates = sorted(candidates.items(), key=lambda x:x[1][1], reverse=True)
    #print(sorted_candidates[0][1][1])
    return sorted_candidates[0][1][0], sorted_candidates[0][0] # r, s

def prepare_new_ciphertext(e, n, s, c):
    if config["with_encryption"]:
        new_c = (c * pow(s, e, n)) % n
    else:
        new_c = (c * s) % n
    return new_c
        
def get_conformant_from_negative(oracle, a, b, si, r, lcm, c, B):
    queries = 0
    a1 = a
    b1 = (r*n + oracle.mmin)//si # todo lcm
    a2 = (r*n + oracle.mmax)//si # todo lcm
    b2 = b
    
    while True:
        in_first = (c >= a1 and c <= b1) # for debugging
        in_second = (c >= a2 and c <= b2) # for debugging
        if not in_first and not in_second:
            pass
            #print("implementation error 4")
            #sys.exit(1)
            
        if b1 == a2 or b1 == a2-1:
            return queries, a1, b2, r
            
        if a1 == b1:
            print("hhhhmmmm1")
            tr, ts = get_s_for_number(oracle, n, B, a1, a2, b2, max_attempts=1000)
            if ts != None:
                new_c = prepare_new_ciphertext(e, n, ts, c) # for FFT this can't work always
                conformant = oracle.call(new_c)
                queries += 1
                if conformant:
                    return queries, a1, b1, r
                else:
                    return queries, a2, b2, r
            #else:
            #    return queries, a1, b2, r # giving up, switch back to searching conforming messages
        if a1 >= b1:
            return queries, a1, b2, r # giving up, switch back to searching conforming messages
            #return queries, a2, b2, r # not working

        if a2 == b2:
            print("hhhhmmmm2")
            tr, ts = get_s_for_number(oracle, n, B, a2, a1, b1, max_attempts=1000)
            if ts != None:
                new_c = prepare_new_ciphertext(e, n, ts, c) # for FFT this can't work always
                conformant = oracle.call(new_c)
                queries += 1
                if conformant:
                    return queries, a2, b2, r
                else:
                    return queries, a1, b1, r
            #else:
            #    return queries, a1, b2, r # giving up, switch back to searching conforming messages
        if a2 >= b2:
            return queries, a1, b2, r # giving up, switch back to searching conforming messages
            #return queries, a1, b1, r # not working

        r1, s1 = find_best_s(oracle, a1, b1, n, B, B, B, a2, b2)
        #if s1 * b1 - s1 * a1 > B:
        #    print("fix it 1")

        r2, s2 = find_best_s(oracle, a2, b2, n, B, B, B, a1, b1)
        #if s2 * b2 - s2 * a2 > B:
        #    print("fix it 2")
        
        if r1 == None and r2 == None:
            print("giving up for this case")
            return queries, a1, b2, r # giving up, switch back to searching conforming messages
        
        if r1 != None:
            new_c = prepare_new_ciphertext(e, n, s1, c)
            conformant = oracle.call(new_c)
            queries += 1
            if conformant:
                new_a, new_b = a1, b1
                na, nb = get_new_bounds(s1, r1, n, oracle.mmin, oracle.mmax)
                if na > new_a:
                    new_a = na
                    #new_a = divide_ceil(new_a, lcm) * lcm
                if nb < new_b:
                    new_b = nb
                    #new_b = (new_b // lcm) * lcm
                if c < new_a or c > new_b:
                    print("implementation error 5")
                    sys.exit(1)
                return queries, new_a, new_b, r1

        if r2 != None:
            new_c = prepare_new_ciphertext(e, n, s2, c)
            conformant = oracle.call(new_c)
            queries += 1
            if conformant:
                new_a, new_b = a2, b2
                na, nb = get_new_bounds(s2, r2, n, oracle.mmin, oracle.mmax)
                if na > new_a:
                    new_a = na
                    new_a = divide_ceil(new_a, lcm) * lcm
                if nb < new_b:
                    new_b = nb
                    new_b = (new_b // lcm) * lcm
                if c < new_a or c > new_b:
                    print("implementation error 6")
                    sys.exit(1)
                return queries, new_a, new_b, r2

        if r1 != None:
            if a1 * s1 >= r1*n + oracle.mmin:
                a1 = (r1*n + oracle.mmax) // s1 # todo: divide_ceil
                #a1 = divide_ceil(a1, lcm) * lcm
                if a1 * s1 <= r1 * n + oracle.mmax:
                    a1 += 1
            if b1 * s1 < r1*n + oracle.mmax:
                b1 = (r1*n + oracle.mmin) // s1 # todo: divide_ceil
                #b1 = (b1 // lcm) * lcm

        if r2 != None:
            if a2 * s2 >= r2*n + oracle.mmin:
                a2 = (r2*n + oracle.mmax) // s2 # todo: divide_ceil
                #a2 = divide_ceil(a2, lcm) * lcm
                if a2 * s2 <= r2 * n + oracle.mmax:
                    a2 += 1
            if b2 * s2 < r2*n + oracle.mmax:
                b2 = (r2*n + oracle.mmin) // s2 # todo: divide_ceil
                b2 = (b2 // lcm) * lcm
            
        if in_first:
            if c < a1 or c > b1:
                pass
                #print("implementation error 7")
                #sys.exit()
        if in_second:
            if c < a2 or c > b2:
                pass
                #print("implementation error 8")
                #sys.exit()
            
def get_conformant_checking_bounds_candidates(oracle, candidate_bounds, temporary_r, c, 
                                              new_a, new_b, mmin, mmax, rsa, n, B, e):
    queries_all = 0
    while True:
        for ind, b1 in enumerate(candidate_bounds):
            r = temporary_r[ind]
            ta = b1[0]
            tb = b1[1]
            si, r, queries = get_conformant(oracle, r, c, ta, tb, rsa, n, B, e, 
                                        check_only_one_r=True)
            queries_all += queries
            if si != None:
                #print "Found s: %s, queries for parallel: %s" % (si, queries_all)
                candidate_bounds1 = get_candidate_bounds(si, new_a, new_b, oracle.mmin, oracle.mmax, n)
                bounds = []
                for b1 in candidate_bounds:
                    for b2 in candidate_bounds1:
                        m1 = max(b1[0], b2[0])
                        m2 = min(b1[1], b2[1])
                        if m1 <= m2: # intersection not empty
                            bounds.append([m1, m2]) 
                return bounds, queries_all, si
            temporary_r[ind] += 1

def determine_proper_bounds_parallel_threads(oracle, rsa, n, B, e, a, b, candidate_bounds, si):
    oracle_queries = 0
    while True:
        temporary_r = []
        for b1 in candidate_bounds:
            r = 2 * b1[0] * si // n
            r = 2*r
            temporary_r.append(r)
        bounds, queries, si = get_conformant_checking_bounds_candidates(oracle,
                                                            candidate_bounds, temporary_r, 
                                                            c, a, b,
                                                            oracle.mmin, oracle.mmax, 
                                                            rsa, n, B, e)
        oracle_queries += queries
        if len(bounds) == 1:
            new_a, new_b = bounds[0]
            return new_a, new_b, r, si, oracle_queries
        else:
            candidate_bounds = bounds

def determine_proper_bounds(oracle, rsa, n, B, e, a, b, candidate_bounds, si):
    oracle_queries = 0
    while True:
        r = 2 * candidate_bounds[0][0] * si // n
        #ta = candidate_bounds[0][0] # this is how it is in Bardou impl., but it is not ok
        #tb = candidate_bounds[0][1] # this is how it is in Bardou impl., but it is not ok
        si, r, queries = get_conformant(oracle, r, c, a, b, rsa, n, B, e)
        oracle_queries += queries
        candidate_bounds1 = get_candidate_bounds(si, a, b, oracle.mmin, oracle.mmax, n)
        bounds = []
        for b1 in candidate_bounds:
            for b2 in candidate_bounds1:
                m1 = max(b1[0], b2[0])
                m2 = min(b1[1], b2[1])
                if m1 <= m2: # intersection not empty
                    bounds.append([m1, m2]) 
        if len(bounds) == 1:
            new_a, new_b = bounds[0]
            return new_a, new_b, r, si, oracle_queries
            break
        else:
            candidate_bounds = bounds
                       
def find_plaintext(config, c, rsa, optimized_si=False, use_negative=False, use_mod_trimmer=False): 
    # use_negative can be used only in TTT oracle (because in weaker oracles we cannot
    # be sure that an answer about a message not being a conformant really
    # means that the message is not conformant (it could just be that the
    # padding is not valid)
    if use_negative:
        if config["noterm"] == False or config["shortpad"] == False:
            print("use_negative cannot be used for this kind of an oracle")
            sys.exit()
    
    modBits = Crypto.Util.number.size(rsa.n)
    k = ceil_div(modBits, 8) # Convert from bits to bytes (length of n in bytes)
    B = pow(2, 8*(k-2))

    oracle = Oracle(rsa, B, config["noterm"], config["shortpad"])
    oracle_queries = 0
    
    if config["use_trimmer"]:
        _n_div_9B = 2*n // (9*B)
        if use_mod_trimmer:
            trimmer = ModTrimmer(config, oracle, c)
        else:
            trimmer = Trimmer(config, oracle, c)
        best_fractions, lcm, oracle_calls = trimmer.get_best_fractions(_n_div_9B, oracle_queries)
        oracle_queries += oracle_calls
        lower_fraction, upper_fraction = best_fractions

        new_a = oracle.mmin * lower_fraction[1] // lower_fraction[0]
        new_a = divide_ceil(new_a, lcm) * lcm
        new_b = divide_ceil(oracle.mmax * upper_fraction[1], upper_fraction[0])
        new_b = (new_b // lcm) * lcm
    else:
        new_a = oracle.mmin
        new_b = oracle.mmax

    start = (n+new_a)//new_b
    #print "Searching s1 from " + str(start)
            
    si = start
    conformant = False
    while True:
        rs = get_rs(si, new_a, new_b, n, oracle.mmin, oracle.mmax)
        if len(rs) != 0:
            if config["with_encryption"]:
                new_c = (c * pow(si, e, n)) % n
            else:
                new_c = (c * si) % n
            conformant = oracle.call(new_c)
            oracle_queries += 1
            if conformant:
                break
        si += 1 
    
    # debugging:
    for i in range(si+1):
        break
        bla = (c * i) % n
        if bla > oracle.mmin and bla < oracle.mmax:
            print(i)
            
    print("Found s1: %s; oracle queries: %s" % (si, oracle_queries))
    good_s = [si]
    s1_oracle_queries = oracle_queries

    candidate_bounds = get_candidate_bounds(si, new_a, new_b, oracle.mmin, oracle.mmax, n)
    if len(candidate_bounds) == 1:
        new_a, new_b = candidate_bounds[0]
        r = new_a * si // n
        print("---")
        print(r)
        print(get_intersect_rs(oracle, n, B, c, 0, 10))
    else:
        if config["use_parallel_threads_method"]:
            new_a, new_b, r, si, qs = determine_proper_bounds_parallel_threads(oracle, rsa, n, B, e, new_a, new_b, candidate_bounds, si)
            oracle_queries += qs
            print("parallel threads determine proper bounds queries: %s" % qs)
        else:
            # find another si for which the message is conformant
            new_a, new_b, r, si, qs = determine_proper_bounds(oracle, rsa, n, B, e, new_a, new_b, candidate_bounds, si)
            oracle_queries += qs
            print("determine proper bounds queries: %s" % qs)
    if c < new_a or c > new_b:
        print("implementation error 1")

    good_r = [r]
    
    s_count = 1
    if use_negative:
        # When a multiplied message is reported to be non conformant in TTT oracle, we know where
        # outside a conformant interval the message lies.
        # This significantly improve finding s2, s3, ... (for s1 it cannot be used)
        while True:
            r = 2*r

            min_si = 1 + (r*n + oracle.mmin) // new_b
            max_si = (r*n + oracle.mmax) // new_a
            #for si in range(min_si, max_si+1):
            for si in range(min_si, min_si+1): # todo: check all si
                if config["with_encryption"]:
                    new_c = (c * pow(si, e, n)) % n
                else:
                    new_c = (c * si) % n
                conformant = oracle.call(new_c)
                oracle_queries += 1
                if conformant:
                    na, nb = get_new_bounds(si, r, n, oracle.mmin, oracle.mmax)
                    if na > new_a:
                        new_a = na
                        new_a = divide_ceil(new_a, lcm) * lcm
                    if nb < new_b:
                        new_b = nb
                        new_b = (new_b // lcm) * lcm
                    if c < new_a or c > new_b:
                        print("implementation error 3")
                        sys.exit(1)
                    if new_b == new_a:
                        print("oracle queries: %s" % (oracle_queries))
                        return oracle_queries, s1_oracle_queries
                else:
                    done = False
                    old_r = r
                    old_a = new_a
                    old_b = new_b
                    if config["noterm"] == False or config["shortpad"] == False:
                        pass
                    else:
                        if si * new_a > r*n + oracle.mmin:
                            new_a = (r*n + oracle.mmax)//si
                            new_a = divide_ceil(new_a, lcm) * lcm #todo ??
                            done = True
                        if si * new_b < r*n + oracle.mmax:
                            new_b = (r*n + oracle.mmin)//si
                            #if new_b * si < r*n + oracle.mmin:
                            #    new_b += 1
                            new_b = (new_b // lcm) * lcm # todo ??
                            done = True
                    if not done:
                        #print(new_b - new_a)
                        if c * si % n > oracle.mmin and c * si % n < oracle.mmax:
                            print("this is conformant")

                        qs, new_a, new_b, r = get_conformant_from_negative(oracle, new_a, new_b, si, r, lcm, c, B)
                        oracle_queries += qs
                        
                        if new_b == new_a:
                            print("oracle queries: %s" % (oracle_queries))
                            return oracle_queries, s1_oracle_queries
    else:
        unsuccessful_rs = []
        while True:
            if optimized_si:
                tmp_s = 2 * B // (new_b - new_a)
                r = tmp_s * new_a // n
                si, r, queries = get_conformant_optimized_si(oracle, r, c, new_a, new_b, rsa, n, B, e, \
                                                          unsuccessful_rs)
            else:
                r = 2*r
                si, r, queries = get_conformant(oracle, r, c, new_a, new_b, rsa, n, B, e)
            if len(good_s) < 500:
                good_s.append(si)
                good_r.append(r)

            oracle_queries += queries
            # r mora deliti (s-1)
            s_count += 1
            #rs = get_rs(si, new_a, new_b, n, oracle.mmin, oracle.mmax)
            #r = rs[0]
            candidate_bounds = get_candidate_bounds(si, new_a, new_b, oracle.mmin, oracle.mmax, n)
            #if len(rs) > 1:
            if len(candidate_bounds) > 1:
                #print(rs)
                print("this does not happen in TTT, but in other oracles it can")
                if config["use_parallel_threads_method"]:
                    new_a, new_b, r, si, qs = determine_proper_bounds_parallel_threads(oracle, rsa, n, B, e, new_a, new_b, candidate_bounds, si)
                    oracle_queries += qs
                    print("calls to determine bounds (parallel): %s" % qs)
                else:
                    new_a, new_b, r, si, qs = determine_proper_bounds(oracle, rsa, n, B, e, new_a, new_b, candidate_bounds, si)
                    oracle_queries += qs
                    print("calls to determine bounds: %s" % qs)
            else:
                new_a, new_b = candidate_bounds[0]
                r = new_a * si // n
            new_a = divide_ceil(new_a, lcm) * lcm
            new_b = (new_b // lcm) * lcm
            
            nn_a = new_a
            nn_b = new_b
            for ind1, si1 in enumerate(good_s):
                break
                for ind2, si2 in enumerate(good_s):
                    if ind2 <= ind1:
                        continue
                    ri1 = good_r[ind1]
                    ri2 = good_r[ind2]
                    
                    na = ((ri2 - ri1)*n - B)//(si2 - si1)
                    if na * (si2-si1) < (ri2-ri1)*n - B:
                        na += 1
                    nb = ((ri2-ri1)*n + B)//(si2 - si1)
                    if na > c or nb < c:
                        sys.exit("go somewhere")
                    if na > new_a:
                        #print("tra1")
                        #print((na-nn_a)/B)
                        print("%s, %s" % (ind1, ind2))
                        new_a = na
                        new_a = divide_ceil(new_a, lcm) * lcm
                    if nb < new_b:
                        #print("tra2")
                        #print((nn_b-nb)/B)
                        print("%s, %s" % (ind1, ind2))
                        new_b = nb
                        new_b = (new_b // lcm) * lcm
            #print("=======================")
            
            
            
            if c < new_a or c > new_b:
                print("implementation error 2")
                sys.exit(1)
            if new_b == new_a:
                print("oracle queries: %s" % (oracle_queries))
                print("--------------------------------------------------")
                print(new_a)
                return oracle_queries, s1_oracle_queries

if __name__ == "__main__": 
    config = {}
    config["with_encryption"] = False # False if you want to speed up the computation (no real encryption/decrypton in this case)
    config["noterm"] = False # allow nonterminated padding (no zero byte after padding string)
    config["shortpad"] = False # allow short padding (zero byte in the first 8)
    config["use_parallel_threads_method"] = True
    config["use_trimmer"] = True
    # trimmers are fractions [num, den]
    config["num_trimmers"] = 1500
    config["max_all_fractions_search"] = 50 # for how much num and den can differ for small fractions
    config["max_den"] = 400 # the highest den that is checked
    config["max_denominators"] = 5000
    config["trimmer_enable_filtering"] = False

    queries = []
    queries_check = []
    s1_queries = []
    s1_queries_check = []
    # to get a realistic mean the number of repetitions needs to be higher than 1000
    for i in range(1):
        print("------------ %s ------------" % i)
        r = RSA.generate(1024)
        #r = RSA.generate(2048)
        n = r.n
        e = r.e
        d = r.d
        
        print(n)
        print(e)
        print(d)
        
        rsa = RSA1(n, e, d)
        msg = "Hello"
        c = rsa.encrypt(msg) # if with_enryption is set to False, only padding will be applied (no encryption)
        # if for debugging reasons you want to try to repeat the execution, 
        # you need to set n, e, d, c (c has some randomnes due to padding)
        print(c)
        
        #config["trimmer_enable_filtering"] = False
        q1, s1_calls1 = find_plaintext(config, c, rsa, optimized_si=False, use_negative=False)
        queries.append(q1)
        s1_queries.append(s1_calls1)

        print("---------------------------------------------------------------------------")
        #config["trimmer_enable_filtering"] = True
        #q = find_plaintext(config, c, rsa)
        #q = find_plaintext(config, c, rsa, optimized_si=True)
        #q2, s1_calls2 = find_plaintext(config, c, rsa, optimized_si=True, use_negative=False)
        #q2, s1_calls2 = find_plaintext(config, c, rsa, optimized_si=False, use_negative=True)
        
        q2, s1_calls2 = find_plaintext(config, c, rsa, optimized_si=False, use_negative=False, use_mod_trimmer=True)

        s1_queries_check.append(s1_calls2)
        queries_check.append(q2)

    sorted_queries = sorted(queries)
    print(sorted_queries)
    mean = sum(queries)/len(queries)
    print("mean: %s" % mean)
    
    if len(queries) % 2 == 0:
        median = (sorted_queries[-1 + len(sorted_queries)//2] + sorted_queries[len(sorted_queries)//2]) // 2
    else:
        median = sorted_queries[len(sorted_queries)//2]
    print("median: %s" % median)
    
    s1_mean = sum(s1_queries)/len(s1_queries)
    print("s1 mean: %s" % s1_mean)
    s1_without = (mean - s1_mean)
    print("without s1: %s" % s1_without) 

    # only if you are comparing number of calls between different configurations (for example 
    # using optimized_si = False and optimized_si = True)
    if True:
        print("================================")
        sorted_queries_check = sorted(queries_check)
        print(sorted_queries_check)
        mean = sum(queries_check)/len(queries_check)
        print("mean: %s" % mean)
    
        if len(queries_check) % 2 == 0:
            median = (sorted_queries_check[-1 + len(sorted_queries_check)//2] + 
                  sorted_queries_check[len(sorted_queries_check)//2]) // 2
        else:
            median = sorted_queries_check[len(sorted_queries_check)//2]
        print("median: %s" % median)

        s1_mean2 = sum(s1_queries_check)/len(s1_queries_check)
        print("s1 mean: %s" % s1_mean2)
        s1_without1 = (mean - s1_mean2)
        print("without s1: %s" % s1_without1)
        
        impr = ((s1_without - s1_without1)/s1_without) * 100
        # this is significant when use_negative:
        print("oracle queries reduced by %s percents from s2 on" % impr)

    


