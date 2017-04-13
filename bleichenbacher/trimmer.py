from Crypto.Util.number import *
from util import divide_ceil, get_intersect_rs, letsee

class Trimmer():
    def __init__(self, config, oracle, c):
        self.config = config
        self.oracle = oracle
        self.rsa = oracle.rsa
        self.mmin = oracle.mmin
        self.mmax = oracle.mmax
        self.c = c
        
    def _get_fractions(self):
        max_t = 4096
        trimmers = []
        for t in range(2, max_t):
            #min_u = 2*t//3
            #max_u = 1.5*t
            #u_values = range(min_u, max_u)
            u_values = range(max(1, t-self.config["max_all_fractions_search"]), t)

            #u_values = [t-1]
            if self.config["noterm"] == False or self.config["shortpad"] == False:
                u_values = [t-2, t-1]
            for u in u_values:
                if t > self.config["max_den"]:
                    continue
                if u == t:
                    continue
                if u * self.mmax > t * self.mmin and GCD(u, t) == 1:
                    trimmers.append([u, t])
                if len(trimmers) > self.config["num_trimmers"]//2: # TODO
                    break
        return trimmers

    def get_best_fractions(self, _n_div_9B, oracle_queries):
        trimmers = self._get_fractions()
        #trimmers = self._get_fractions_old(_n_div_9B)
        dens = []
        self.used_fractions = []
 
        mmax = self.mmax
        mmin = self.mmin
        # lower: 
        best_lower = [1, 1]
        for tr in trimmers:
            num, den = tr
            
            if den in dens:
                continue
            
            if num * mmax < den * mmin: # self.mmin, self.mmax are adapted when fraction found
                #print("at least one!!!!!!!!!!!")
                continue
            
            self.used_fractions.append([num, den])
            
            den_inv = inverse(den, self.rsa.n)

            if self.config["with_encryption"]:
                new_c = (self.c * pow(num * den_inv, self.rsa.e, self.rsa.n)) % self.rsa.n
            else:
                new_c = (num * den_inv * self.c) % self.rsa.n
            conformant = self.oracle.call(new_c)
            oracle_queries += 1
            if conformant:
                #print "conformant: [%s, %s], queries: %s" % (num, den, oracle_calls + oracle_queries)
                print("lower: %s, %s" % (num, den))
                if den not in dens:
                    dens.append(den)
                fraction_val = best_lower[0]/best_lower[1]
                tmp_fraction_val = num/den
                if tmp_fraction_val < fraction_val:
                    best_lower = [num, den]
                    mmin = mmin * best_lower[1] // best_lower[0]
                # debugging:
                # 
                s1 = num*den_inv # we know m*s1 is conformant 
                # this should be very small compared to n: s1*c should be very close to some n*x
                diff = (self.rsa.n - s1*self.c) % self.rsa.n
                    
        # upper: 
        best_upper = [1, 1]
        for tr in trimmers:
            # TODO: this should actually not be needed as all dens should already be found
            # and this can be checked in th last step in this function - NOT TRUE, it is needed
            den, num = tr

            if den in dens:
                continue
            
            if den * mmax < num * mmin: # self.mmin, self.mmax are adapted when fraction found
                #print("at least one!!!!!!!!!!!")
                continue
            
            den_inv = inverse(den, self.rsa.n)

            self.used_fractions.append([num, den])

            if self.config["with_encryption"]:
                new_c = (self.c * pow(num * den_inv, self.rsa.e, self.rsa.n)) % self.rsa.n
            else:
                new_c = (num * den_inv * self.c) % self.rsa.n
            conformant = self.oracle.call(new_c)
            oracle_queries += 1
            if conformant:
                #print "conformant: [%s, %s], queries: %s" % (num, den, oracle_calls + oracle_queries)
                print("upper: %s, %s" % (num, den))
                if den not in dens:
                    dens.append(den)
                fraction_val = best_upper[0]/best_upper[1]
                tmp_fraction_val = num/den
                if tmp_fraction_val > fraction_val:
                    best_upper = [num, den]
                    mmax = divide_ceil(mmax * best_upper[1], best_upper[0])

        den, lcm = self.get_denominator(dens)

        #den1 = best_lower[1]
        #den2 = best_upper[1]
        #t1 = (inverse(den1, self.rsa.n)*self.c%self.rsa.n)/self.oracle.B 
        #t2 = (inverse(den2, self.rsa.n)*self.c%self.rsa.n)/self.oracle.B 
        #print(letsee(self.oracle, self.rsa.n, self.oracle.B, self.c, 0, 20))
        #print(get_intersect_rs(self.oracle, self.rsa.n, self.oracle.B, self.c, 0, 20))

        min_num = den * self.mmin // self.mmax
        numerators = range(min_num, den)
        for num in numerators:
            f = [num, den]
            den_inv = inverse(den, self.rsa.n)
            if f not in self.used_fractions:
                fractionVal = best_lower[0]/best_lower[1]
                tmpFractionVal = num/den
                if tmpFractionVal >= fractionVal:
                    continue
                if self.config["with_encryption"]:
                    new_c = (self.c * pow(num * den_inv, self.rsa.e, self.rsa.n)) % self.rsa.n
                else:
                    new_c = (num * den_inv * self.c) % self.rsa.n
                conformant = self.oracle.call(new_c)
                oracle_queries += 1
                if conformant:
                    #print "conformant: [%s, %s], queries: %s" % (num, den, calls + oracle_queries)
                    best_lower = [num, den]
        
        max_num = den * self.mmax // self.mmin
        numerators = range(max_num, den, -1)
        for num in numerators:
            den_inv = inverse(den, self.rsa.n)
            #if [den, num] not in self.used_fractions:
            if [num, den] not in self.used_fractions: # mistake in Bardou?
                fractionVal = best_upper[0]/best_upper[1]
                tmpFractionVal = num/den
                if tmpFractionVal <= fractionVal:
                    continue
                if self.config["with_encryption"]:
                    new_c = (self.c * pow(num * den_inv, self.rsa.e, self.rsa.n)) % self.rsa.n
                else:
                    new_c = (num * den_inv * self.c) % self.rsa.n
                conformant = self.oracle.call(new_c)
                oracle_queries += 1
                if conformant:
                    #print("conformant: [%s, %s], queries: %s" % (num, den, calls + oracle_queries))
                    best_upper = [num, den]
                    break # this is ok, futher nums won't be better
        print(best_lower)
        print(best_upper)
        
        dividors = []
        for i in range(2, 10000):
            if self.c % i == 0:
                dividors.append(i)
        #print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        #print("dividors: %s" % dividors)
        for div in dividors:
            break
            div_inv = inverse(den, self.rsa.n)
            fractions = []
            for num_i in range(div - 100, div+100):
                new_c = (num_i * div_inv * self.c) % self.rsa.n
                conformant = self.oracle.call(new_c)
                if conformant:
                    fractions.append([num_i, div])
            print("--")
            print(fractions) 
        
        rs = get_intersect_rs(self.oracle, self.rsa.n, self.oracle.B, self.c, 0, 1000)
        rs1 = map(lambda x:x[0], rs)
        #print("++")
        #print("rs: %s" % list(rs1)) 
            

        print("oracle calls for trimmer: %s" % oracle_queries)
        return [best_lower, best_upper], lcm, oracle_queries
                    
        
    def get_denominator(self, dens):
        # least common multiple
        if len(dens) == 0:
            lcm = 1
        else:
            lcm = dens[0]
            for i in range(1, len(dens)):
                lcm = lcm * dens[i] // GCD(lcm, dens[i])
        if lcm < self.config["max_denominators"]:
            den = lcm
        else:
            for i in range(1, min(lcm//2, self.config["max_denominators"])):
                if lcm % i == 0:
                    den = i
        return den, lcm 

    def _get_fractions_old(self, _n_div_9B):
        trimmers = []
        j = 2

        max_search = self.config["max_all_fractions_search"]
        max_den = self.config["max_den"]
        num_trimmers = self.config["num_trimmers"]

        # Smaller denominators divide ciphertexts more often
        # so we first check all small fractions.
        trims = []
        for k in range(5, max(max_search+1, 5+1)):                                   
            for i in range(2, k-1):
                j = k - i
                if (j != 1 and i < j and j < _n_div_9B and i * self.mmax > j * self.mmin and GCD(i, j) == 1):
                    trimmers.append([i, j])
                    trims.append((i, j))
        
        k = 1
        while len(trimmers) < num_trimmers//2:
            for j in range(max(max_search, 5)//2 + 1, max_den+1):
                i = j - k
                while (i != 1 and i < j and i * self.mmax > j * self.mmin):
                    if [i, j] not in trimmers and GCD(i, j) == 1:
                        trimmers.append([i, j])
                        break
                    i -= 1
                    if len(trimmers) >= num_trimmers//2:
                        break
                if len(trimmers) >= num_trimmers//2:
                    break
            k += 1
        #print "loop num: " + str(k)
        #print "length of trimmers: " + str(len(trimmers)) + " last j: " + str(j)

        return trimmers

       
        
        
        
        
        