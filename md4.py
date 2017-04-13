# md4 implementation taken from https://gist.github.com/bonsaiviking/5644414
# other functions are for Wang attack

import struct
import sys
import math

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def inv_leftrotate(i, n):
    return ((i << (32-n)) & 0xffffffff) | (i >> n)

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, data=""):
        self.remainder = data
        self.count = 0
        self.h = [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
                ]
        self.X_mod = None
        self.tweaked_h = None
        self.conditions = []
        self.extra_conditions = []
        self.all_conditions = [] # should be met when modifying the first round, however, extra conditions
        # are not required any more after modifications of blocks in round 2
        self.r_diff = [[], [6], [10, -7], [25], [], [13], [18, 19, -20, 21], [-12, -13, 14], [16], [19, -20, -21, 22, -25], [-29], [31], [22, 25], [-26, -28, 29], [], [18],
                       [-25, 26, -28, -31], [], [], [-29, 31], [-28, 29, -31], [], [], [], [], [],
                       [], [], [], [], [], [], [], [], [], [-31], [-31], [], [], [], []]
        
            
        self.conditions = [[1, 6, 'a', 'b', 'same'], 
                           [2, 6, 'd', 0], [2, 7, 'd', 'a', 'same'], [2, 10, 'd', 'a', 'same'],
                           [3, 6, 'c', 1], [3, 7, 'c', 1], [3, 10, 'c', 0], [3, 25, 'c', 'd', 'same'],
                           [4, 6, 'b', 1], [4, 7, 'b', 0], [4, 10, 'b', 0], [4, 25, 'b', 0],
                           [5, 7, 'a', 1], [5, 10, 'a', 1], [5, 25, 'a', 0], [5, 13, 'a', 'b', 'same'],
                           [6, 13, 'd', 0], [6, 18, 'd', 'a', 'same'], [6, 19, 'd', 'a', 'same'], [6, 20, 'd', 'a', 'same'], [6, 21, 'd', 'a', 'same'], [6, 25, 'd', 1],
                           [7, 12, 'c', 'd', 'same'], [7, 13, 'c', 0], [7, 14, 'c', 'd', 'same'], [7, 18, 'c', 0], [7, 19, 'c', 0], [7, 20, 'c', 1], [7, 21, 'c', 0],
                           [8, 12, 'b', 1], [8, 13, 'b', 1], [8, 14, 'b', 0], [8, 16, 'b', 'c', 'same'], [8, 18, 'b', 0], [8, 19, 'b', 0], [8, 20, 'b', 0], [8, 21, 'b', 0],
                           [9, 12, 'a', 1], [9, 13, 'a', 1], [9, 14, 'a', 1], [9, 16, 'a', 0], [9, 18, 'a', 0], [9, 19, 'a', 0], [9, 20, 'a', 0], [9, 22, 'a', 'b', 'same'], [9, 21, 'a', 1], [9, 25, 'a', 'b', 'same'],
                           [10, 12, 'd', 1], [10, 13, 'd', 1], [10, 14, 'd', 1], [10, 16, 'd', 0], [10, 19, 'd', 0], [10, 20, 'd', 1], [10, 21, 'd', 1], [10, 22, 'd', 0], [10, 25, 'd', 1], [10, 29, 'd', 'a', 'same'],
                           [11, 16, 'c', 1], [11, 19, 'c', 0], [11, 20, 'c', 0], [11, 21, 'c', 0], [11, 22, 'c', 0], [11, 25, 'c', 0], [11, 29, 'c', 1], [11, 31, 'c', 'd', 'same'],
                           [12, 19, 'b', 0], [12, 20, 'b', 1], [12, 21, 'b', 1], [12, 22, 'b', 'c', 'same'], [12, 25, 'b', 1], [12, 29, 'b', 0], [12, 31, 'b', 0], # something wrong with [12, 20, 'b', 1], [12, 21, 'b', 1]
                           [13, 22, 'a', 0], [13, 25, 'a', 0], [13, 26, 'a', 'b', 'same'], [13, 28, 'a', 'b', 'same'], [13, 29, 'a', 1], [13, 31, 'a', 0],
                           [14, 22, 'd', 0], [14, 25, 'd', 0], [14, 26, 'd', 1], [14, 28, 'd', 1], [14, 29, 'd', 0], [14, 31, 'd', 1],
                           [15, 18, 'c', 'd', 'same'], [15, 22, 'c', 1], [15, 25, 'c', 1], [15, 26, 'c', 0], [15, 28, 'c', 0], [15, 29, 'c', 0],
                           [16, 18, 'b', 0], [16, 25, 'b', 1], [16, 25, 'c', 1], [16, 26, 'b', 1], [16, 28, 'b', 1], [16, 29, 'b', 0],
                           [17, 18, 'a', 'c', 'same'], [17, 25, 'a', 1], [17, 26, 'a', 0], [17, 28, 'a', 1], [17, 31, 'a', 1],#,
                           [18, 18, 'd', 'a', 'same'], [18, 25, 'd', 'b', 'same'], [18, 26, 'd', 'b', 'same'], [18, 28, 'd', 'b', 'same'], [18, 31, 'd', 'b', 'same'],
                           [19, 25, 'c', 'd', 'same'], [19, 26, 'c', 'd', 'same'], [19, 28, 'c', 'd', 'same'], [19, 29, 'c', 'd', 'same'], [19, 31, 'c', 'd', 'same'],#,
                           [20, 28, 'b', 'c', 'same'], [20, 29, 'b', 1], [16, 31, 'b', 0],
                           [21, 28, 'a', 1], [21, 31, 'a', 1],
                           [22, 28, 'd', 'b', 'same'],
                           [23, 28, 'c', 'd', 'same'], [23, 29, 'c', 'd', 'different'], [23, 31, 'c', 'd', 'different'], # c_29 = d_29 + 1, c_31 = d_31 + 1
                           #[23, 28, 'c', 'd', 'same'], [23, 29, 'c', 1], [23, 29, 'd', 0], [23, 31, 'c', 1], [23, 31, 'd', 0], # c_29 = d_29 + 1, c_31 = d_31 + 1
                           [24, 31, 'b', 1],
                           [25, 31, 'a', 1]]
        # extra conditions for round 2 (multi-step modifications
        # d 5,18 = a 5,18:
        self.extra_conditions.extend([[2, 13, 'd', 0], [1, 13, 'a', 'b', 'same'], [3, 13, 'c', 0], [4, 13, 'b', 0]])
        self.extra_conditions.extend([[6, 16, 'd', 0], [5, 16, 'a', 'b', 'same'], [7, 16, 'c', 0], [8, 16, 'b', 0]])
        self.extra_conditions.extend([[6, 17, 'd', 0], [5, 17, 'a', 'b', 'same'], [7, 17, 'c', 0], [8, 17, 'b', 0]])
        self.extra_conditions.extend([[15, 19, 'c', 0], [14, 19, 'd', 'a', 'same'], [16, 19, 'b', 'd', 'same'], [17, 19, 'a', 'b', 'same']])
        self.extra_conditions.extend([[15, 21, 'c', 0], [14, 21, 'd', 'a', 'same'], [16, 21, 'b', 'd', 'same'], [17, 21, 'a', 'b', 'same'], [19, 30, 'c', 1]])
        self.extra_conditions.extend([[11, 15, 'c', 0], [10, 15, 'd', 'a', 'same'], [12, 15, 'b', 1], [13, 15, 'a', 1]])
        self.extra_conditions.extend([[11, 18, 'c', 0], [10, 18, 'd', 'a', 'same'], [12, 18, 'b', 1], [13, 18, 'a', 1]])
        self.extra_conditions.extend([[12, 16, 'b', 0], [13, 16, 'a', 0], [14, 16, 'd', 1]])
        self.extra_conditions.extend([[4, 0, 'b', 1], [4, 1, 'b', 1], [4, 2, 'b', 1]])
        self.extra_conditions.extend([[8, 30, 'b', 1]])
        self.extra_conditions.extend([[12, 26, 'b', 1], [12, 27, 'b', 1]])
        self.extra_conditions.extend([[7, 22, 'c', 0], [8, 22, 'b', 0], [6, 22, 'd', 'a', 'same']])
        
        self._sort_conditions()
        print "-----"
            
            
    def _get_block_ind(self, cond):
        block_ind = None
        r = cond[0]
        i = (16-r)%4
            
        # the following dicts are actually redundant, can be implemented without them
        if i == 3: # d
            # a was calculated in previous step (r-1), b in (r-2) ...
            d = {"d": r, "a": r-1, "b": r-2, "c": r-3}
        if i == 2: # c
            d = {"c": r, "d": r-1, "a": r-2, "b": r-3}
        if i == 1: # b
            d = {"b": r, "c": r-1, "d": r-2, "a": r-3}
        if i == 0: # a
            d = {"a": r, "b": r-1, "c": r-2, "d": r-3}
        if len(cond) == 5:
            # find the element from cond that was calculated last and change the block which was used to calculate it:
            if d[cond[2]] < 0:
                #last = cond[3]
                block_ind = self._get_block_used_in_step(d[cond[3]])
            elif d[cond[3]] < 0:
                #last = cond[2]
                block_ind = self._get_block_used_in_step(d[cond[2]])
            else:
                if d[cond[2]] < d[cond[3]]:
                    #last = cond[3] 
                    block_ind = self._get_block_used_in_step(d[cond[3]])
                else:
                    #last = cond[2]
                    block_ind = self._get_block_used_in_step(d[cond[2]])
        if len(cond) == 4:
            block_ind = self._get_block_used_in_step(d[cond[2]])
        return block_ind
    
    def _sort_conditions(self):
        #hh = self._calculate_h_until_break(self.X_mod, r)
        # add the actual block to be modified
        for cond in self.conditions:
            block_ind = self._get_block_ind(cond)
            cond.append(block_ind)
            self.all_conditions.append(cond)
        for cond in self.extra_conditions:
            block_ind = self._get_block_ind(cond)
            cond.append(block_ind)
            self.all_conditions.append(cond)
                
    def _get_pos_before_rotation(self, pos, shift):
        neg = False
        if pos < 0:
            pos = -pos
            neg = True
        b = inv_leftrotate(2**pos, shift)
        b = int(math.log(b, 2))
        if neg:
            return -b
        else:
            return b
        
    def _help(self, bit_positions, shift):
        # bit_positions: bits where there is a difference
        # we want to know what are these differences after left rotation
        new_bit_positions = []
        for e in bit_positions:
            if e >= 0:
                l = leftrotate(2**e, shift)
                di = int(math.log(l, 2))
                new_bit_positions.append(di)
            else:
                l = leftrotate(2**(-e), shift)
                di = int(math.log(l, 2))
                new_bit_positions.append(-di)
        return new_bit_positions 
    
    def _calculate_h_until_break(self, X, round_break):
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
            if r == round_break:
                return h
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
            if r + 16 == round_break:
                return h
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4 
            if r == 3:
                #hc = list(h)
                #hc[i] = leftrotate( (hc[i] + H(hc[(i+1)%4], hc[(i+2)%4], hc[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )
                # [2780388022, 2595687921, 3283406455, 2915609251]
                #print hc
                #print "debugging"
                pass
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )
            if r + 32 == round_break:
                return h

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32
            
    def _get_block_used_in_step(self, step):
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            #h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
            if r == step:
                return k
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            #h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
            if r + 16 == step:
                return k
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4 
            #h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )
            if r + 32 == step:
                return k[r]

    def modify_message(self, chunk):
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        self.X_mod = list(X) # deep copy
        self.tweaked_h = list(self.h) # deep copy
        
        # Round 1
        s = (3,7,11,19)
        # single-step modifications
        #for r in xrange(16):
        for r in xrange(17): # also for r = 16 here 
            # each time we calculate what is h value (stored in tweaked_h) at step r
            # but we do each time from the beginning because we just modified one block in X_mod
            # (for r = 0 we calculate a1, then X_0 is modified, for r = 1 we 
            # calculate d1 but using modified X_0 and original X_1, for r = 2 we
            # calculate c1 with modified X_0 and X_1 and original X_2 ... )
            self.tweaked_h = self._calculate_h_until_break(self.X_mod, r)
            mapping = {"a": 0, "b":1, "c":2, "d":3}
            # apply conditions:
            # round 1
            conds_round = filter(lambda x:(x[0] == r), self.all_conditions)
            # sort - first bits first:
            conds_round = sorted(conds_round, key=lambda x:x[1])
            for cond in conds_round:
                bit_position = cond[1]
                if len(cond) == 6:
                    block_ind = cond[-1]
                    ind1 = mapping[cond[2]]
                    ind2 = mapping[cond[3]]
                    el1 = self.tweaked_h[ind1]
                    el2 = self.tweaked_h[ind2]
                    if cond[4] == "same":
                        if (el1 >> bit_position) % 2 != (el2 >> bit_position) % 2:
                            self.X_mod[block_ind] = self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32)
                            
                            # no need for this as conditions take care for problems with bit changing in higher positions as well
                            #bit_to_be_changed = (bit_position+32-s[block_ind%4])%32
                            
                            #x = list(self.X_mod)
                            #if block_ind > 0:
                            #    tt = self._calculate_h_until_break(self.X_mod, block_ind-1)
                            #else:
                            #    tt = self.h
                            #i = (16-block_ind)%4
                            #ff = (tt[i] + F(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + self.X_mod[block_ind]) % 2**32
                            #new_block = ((ff ^ 2**bit_to_be_changed) - (tt[i] + F(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]))) % 2**32
                            #x[block_ind] = new_block
                            #self.X_mod[block_ind] = new_block
                            #test = self._calculate_h_until_break(self.X_mod, block_ind)
                            #test1 = self._calculate_h_until_break(x, block_ind)
                            #if abs(test1[i] - test[i]) != 2**bit_position:
                            #    sys.exit("fix1")
                            #diff = self.diff_in_which_bits(test[i], test1[i])
                            #if diff != [bit_position]:
                            #    sys.exit("trara1")
                            #if new_block != self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32):
                            #    pass
                    if cond[4] == "different":
                        if (el1 >> bit_position) % 2 == (el2 >> bit_position) % 2:
                            self.X_mod[block_ind] = self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32)
                if len(cond) == 5:
                    block_ind = cond[-1]
                    ind1 = mapping[cond[2]]
                    el1 = self.tweaked_h[ind1]
                    if (el1 >> bit_position) % 2 != cond[3]:
                        self.X_mod[block_ind] = self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32)
                        
                        # no need for this as conditions take care for problems with bit changing in higher positions as well
                        #bit_to_be_changed = (bit_position+32-s[block_ind%4])%32
                        
                        #x = list(self.X_mod)
                        #if block_ind > 0:
                        #    tt = self._calculate_h_until_break(self.X_mod, block_ind-1)
                        #else:
                        #    tt = self.h
                        #i = (16-block_ind)%4
                        #ff = (tt[i] + F(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + self.X_mod[block_ind]) % 2**32
                        #new_block = ((ff ^ 2**bit_to_be_changed) - (tt[i] + F(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]))) % 2**32
                        #
                        #x[block_ind] = new_block
                        #self.X_mod[block_ind] = new_block
                        #test = self._calculate_h_until_break(self.X_mod, block_ind)
                        #test1 = self._calculate_h_until_break(x, block_ind)
                        #if abs(test1[i] - test[i]) != 2**bit_position:
                        #    sys.exit("fix2")
                        #diff = self.diff_in_which_bits(test[i], test1[i])
                        #if diff != [bit_position]:
                        #    sys.exit("trara2")
                        #if new_block != self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32):
                        #    pass
                self.tweaked_h = self._calculate_h_until_break(self.X_mod, r)
        
        cnds = self._check_conditions(self.X_mod)
        if cnds != []:
            print "well, you should fix modifying messages - like in multi step"
            return False
            
                            
        # multi-step modifications
        for r in xrange(16):
            self.tweaked_h = self._calculate_h_until_break(self.X_mod, r + 16)
            mapping = {"a": 0, "b":1, "c":2, "d":3}
            # apply conditions:
            # round 2
            conds_round = filter(lambda x:(x[0] == r + 16), self.all_conditions)
            # sort - first bits first:
            conds_round = sorted(conds_round, key=lambda x:x[1])
            
            for cond in conds_round:
                bit_position = cond[1]
                    
                if len(cond) == 6:
                    block_ind = cond[-1]
                    ind1 = mapping[cond[2]]
                    ind2 = mapping[cond[3]]
                    el1 = self.tweaked_h[ind1]
                    el2 = self.tweaked_h[ind2]
                    if cond[4] == "same":
                        if (el1 >> bit_position) % 2 != (el2 >> bit_position) % 2:
                            #self.X_mod[block_ind] = self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32)
                            
                            ok = self._multi_step_mod(bit_position, r, block_ind, cond)
                            
                            # check: 
                            th = self._calculate_h_until_break(self.X_mod, r + 16)
                            e1 = th[ind1]
                            e2 = th[ind2]
                            unmet_conditions = self._check_conditions(self.X_mod)
                            if unmet_conditions != []:
                                #sys.exit("go to hell")
                                pass
                            if (e1 >> bit_position) % 2 != (e2 >> bit_position) % 2:
                                # should not reach this
                                #sys.exit("hmmmmmmmmmmmmmmmmm1")
                                pass
                            # self._check_conditions() # should pass first round
                            
                            if not ok:
                                return False
                if len(cond) == 5:
                    block_ind = cond[-1]
                    ind1 = mapping[cond[2]]
                    el1 = self.tweaked_h[ind1]
                    if (el1 >> bit_position) % 2 != cond[3]:
                        #self.X_mod[block_ind] = self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32)
                        if cond == [24, 31, 'b', 1, 13]:
                            print "-+"
                        
                        ok = self._multi_step_mod(bit_position, r, block_ind, cond)
                        
                        th = self._calculate_h_until_break(self.X_mod, r + 16)
                        e1 = th[ind1]
                        unmet_conditions = self._check_conditions(self.X_mod)
                        if unmet_conditions != []:
                            #sys.exit("go to hell")
                            pass
                        if (e1 >> bit_position) % 2 != cond[3]:
                            # should not reach this
                            #sys.exit("hmmmmmmmmmmmmmmmmm2")
                            pass
                        # self._check_conditions() # should pass first round
                        
                        if not ok:
                            return False
                
                self.tweaked_h = self._calculate_h_until_break(self.X_mod, r + 16)
                
                #print "%s ------------ %s" % (r, cond)
                #self._check_conditions()
        
        
        uc = self._check_conditions(self.X_mod, break_at=30)
        if uc != []:
            print "conditions not met"
            return False
        return True

    def diff_in_which_bits(self, x, x1):
        x = bin(x)[2:]
        x1 = bin(x1)[2:]
        x = x[::-1] # reverse string
        x1 = x1[::-1]
        
        # eh, no need for maxlen, minlen
        while len(x) < 32:
            x += "0"
            
        while len(x1) < 32:
            x1 += "0"
            
        
        minlen = min(len(x), len(x1))
        maxlen = max(len(x), len(x1))
        
        diff = []
        for i in range(maxlen):
            if i < minlen:
                if x[i] != x1[i]:
                    diff.append(i)
            else:
                diff.append(i)
        return diff
    
    def _multi_step_mod(self, bit_position, r, block_ind, cond):
        #some conditions simply cannot be fixed, for example:
        #>>> cond
        #[19, 28, 'c', 'd', 'same', 8]
        #>>> unmet_conditions
        #[[9, 22, 'a', 'b', 'same', 8]]
        #in this case we need to modify X_8 at 19 (which will change in second round bit 28 and 
        # made cond to hold, but it will change in the first round bit 22 and will break [9, 22, 'a', 'b', 'same', 8]
        
        s1 = (3,7,11,19)
        s2 = (3,5,9,13)
        mapping = {"a": 0, "b":1, "c":2, "d":3}
        
        x = list(self.X_mod) # deep copy
        changed_blocks = {}
        if cond == [18, 18, 'd', 'a', 'same', 4]:
            x[1] = x[1] + 2**6
            changed_blocks[1] = x[1]
            
            x[4] = x[4] - 2**13
            changed_blocks[4] = x[4]
            x[5] = x[5] - 2**13
            changed_blocks[5] = x[5]
            
            tf = self._calculate_h_until_break(self.X_mod, 4)
            tf1 = self._calculate_h_until_break(x, 4)
        elif cond in [[19, 25, 'c', 'd', 'same', 8], [19, 26, 'c', 'd', 'same', 8]]:
            i = cond[1]
            x[5] = x[5] + 2**(i-16)
            changed_blocks[5] = x[5]
            
            x[8] = x[8] - 2**(i-9)
            changed_blocks[8] = x[8]
            x[9] = x[9] - 2**(i-9)
            changed_blocks[9] = x[9]
        elif cond == [19, 28, 'c', 'd', 'same', 8]:
            i = cond[1]
            x[14] = x[14] + 2**8
            changed_blocks[14] = x[14]
        #elif cond == [19, 29, 'c', 'd', 'same', 8]:
        #    i = cond[1]
        #    x[8] = x[8] + 2**20
        #    changed_blocks[8] = x[8]
        elif cond == [19, 30, 'c', 'd', 'same', 8]:
            i = cond[1]
            x[14] = x[14] + 2**10
            changed_blocks[14] = x[14]
        elif cond in [[20, 28, 'b', 'c', 'same', 12], [16, 31, 'b', 0, 12]]:
            i = cond[1]
            x[10] = x[10] + 2**(i-24)
            changed_blocks[10] = x[10]
            
            x[12] = x[12] - 2**(i-13)
            changed_blocks[12] = x[12]
            
            x[14] = x[14] - 2**(i-13)
            changed_blocks[14] = x[14] 
        elif cond == [20, 29, 'b', 1, 12]:
            i = cond[1]
            x[11] = (x[11] + 2**29) % 2**32
            changed_blocks[11] = x[11]
            
            x[12] = x[12] - 2**16
            changed_blocks[12] = x[12]
            
            x[15] = x[15] - 2**16
            changed_blocks[15] = x[15]
        elif cond[:-1] == [23, 31, 'c', 'd', 'different']:
            i = cond[1]
            x[6] = x[6] + 2**11
            changed_blocks[6] = x[6]
            
            x[9] = x[9] - 2**22
            changed_blocks[9] = x[9]
            
            x[10] = x[10] - 2**22
            changed_blocks[10] = x[10]
        else:
            block_ind = self._get_block_used_in_step(r + 16 - 1)
            bit_to_be_changed = (bit_position+32-s2[(r-1)%4])%32 # to make condition in round 2 hold
            
            tt = self._calculate_h_until_break(self.X_mod, r + 16 - 2)
            i = (16-(r-1))%4 
            k = 4*((r-1)%4) + (r-1)//4
            #h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
            #h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
            #(tt[i] + G(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + self.X_mod[k] + 0x5a827999) % 2**32 = (tt[i] + G(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + ff + 0x5a827999) % 2**32
            ff = (tt[i] + G(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + self.X_mod[k] + 0x5a827999) % 2**32
            new_block = ((ff ^ 2**bit_to_be_changed) - (tt[i] + G(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + 0x5a827999)) % 2**32
            #ff1 = (tt[i] + G(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + new_block + 0x5a827999) % 2**32
            
            old_block = list(self.X_mod)[block_ind]
            # new_block = x[block_ind] ^ 2**bit_to_be_changed # new_block from above is more general solution
            x[block_ind] = new_block
            
            al = leftrotate( (tt[i] + G(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + self.X_mod[k] + 0x5a827999) % 2**32, s2[(r+16-1)%4] )
            al1 = leftrotate( (tt[i] + G(tt[(i+1)%4], tt[(i+2)%4], tt[(i+3)%4]) + x[k] + 0x5a827999) % 2**32, s2[(r+16-1)%4] )
            
            tal = list(tt)
            tal[i] = al
            tal1 = list(tt)
            tal1[i] = al1
            if len(cond) == 6:
                ind1 = mapping[cond[2]]
                ind2 = mapping[cond[3]]
                e1 = tal1[ind1]
                e2 = tal1[ind2]
                if (e1 >> bit_position) % 2 != (e2 >> bit_position) % 2:
                    sys.exit("asdfsad 1")
            else:
                ind1 = mapping[cond[2]]
                e1 = tal1[ind1]
                if (e1 >> bit_position) % 2 != cond[3]:
                    sys.exit("asdfsad 2")
                    
            changed_blocks[block_ind] = new_block
            changed_el_ind = (16-block_ind)%4
            
            # th[block_ind] is now different (diff is in changed_el_ind)
            # we now need to make th[block_ind+1], th[block_ind+2], th[block_ind+3], 
            # th[block_ind+4] to be as without the modification - meaning that the only
            # difference will be in changed_el_ind
            for j in range(1, 5):
                if block_ind + j == 16:
                    # there is no room to remove differences - for example if block_ind is 12,
                    # we can change blocks 13, 14, 15, however we cannot use 16 (=0)
                    #return False
                    break
                th = self._calculate_h_until_break(self.X_mod, block_ind+j)
                th1 = self._calculate_h_until_break(x, block_ind+j)
                tmp_changed_el_ind = (16-(block_ind+j))%4
                if th[tmp_changed_el_ind] != th1[tmp_changed_el_ind]:
                    tah = self._calculate_h_until_break(self.X_mod, block_ind+j-1)
                    tah1 = self._calculate_h_until_break(x, block_ind+j-1)
                    
                    ii = tmp_changed_el_ind
                    #d = tah[ii] + F(tah[(ii+1)%4], tah[(ii+2)%4], tah[(ii+3)%4]) + self.X_mod[block_ind + j]
                    #d1 = tah1[ii] + F(tah1[(ii+1)%4], tah1[(ii+2)%4], tah1[(ii+3)%4]) + x[block_ind + j] 
                    #bit_changed = int(math.log(abs(d1-d), 2))
                    aa = (tah[ii] + F(tah[(ii+1)%4], tah[(ii+2)%4], tah[(ii+3)%4]) + 
	                      self.X_mod[block_ind + j] - tah1[ii] - 
	                      F(tah1[(ii+1)%4], tah1[(ii+2)%4], tah1[(ii+3)%4])) % 2**32
                    
                    x[block_ind+j] = aa
                    changed_blocks[block_ind+j] = aa
                    #d2 = tah1[ii] + F(tah1[(ii+1)%4], tah1[(ii+2)%4], tah1[(ii+3)%4]) + x[block_ind + j]
                    
                    t = self._calculate_h_until_break(self.X_mod, block_ind + j)
                    t1 = self._calculate_h_until_break(x, block_ind + j)
                    if t[tmp_changed_el_ind] != t1[tmp_changed_el_ind]:
                        #sys.exit("cannot do it")
                        pass
                    else:
                        pass
                                        
        foo = self._calculate_h_until_break(self.X_mod, 15)
        foo1 = self._calculate_h_until_break(x, 15)
        #if foo != foo1: # after applying modification in blocks 12,13,14,15 this does not hold anymore
        #    sys.exit("go somewhere")
            
        unmet_conditions = self._check_conditions(x)
        if unmet_conditions == [] and cond == [19, 25, 'c', 'd', 'same', 8]:
            pass
        
        if cond in [[19, 29, 'c', 'd', 'same', 8], [19, 31, 'c', 'd', 'same', 8]]:
            pass
        if unmet_conditions != []:
            # we cannot guarantee that after X[block_ind] in round 1 is used, the conditions
            # for this step still hold (for block_ind+j where j from {1,2,3,4} we can do this
            # via the changes above
            print("r: %s; unmet conditions after multi-step mod: %s" % (r, unmet_conditions))
            if r == 3 and unmet_conditions[0][1] == 25:
                pass
            return False
            
        i = (16-r)%4 
        k = 4*(r%4) + r//4
        #h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        
        hm = leftrotate( (foo[i] + G(foo[(i+1)%4], foo[(i+2)%4], foo[(i+3)%4]) + self.X_mod[k] + 0x5a827999) % 2**32, s2[r%4] )
        hm1 = leftrotate( (foo1[i] + G(foo1[(i+1)%4], foo1[(i+2)%4], foo1[(i+3)%4]) + x[k] + 0x5a827999) % 2**32, s2[r%4] )
                                            
        t = self._calculate_h_until_break(self.X_mod, 16)
        t1 = self._calculate_h_until_break(x, 16)
        # difference between t[0] and t1[0] ?
        #  ... + X[0] where X[0] was different in 23
        #bla = t1[0] - t[0]
        #print bla
                            
        for k,v in changed_blocks.iteritems():
            #self.X_mod[k] = v
            self.X_mod[k] = v % 2**32
            
        
        bla = filter(lambda x : x > 4294967295, self.X_mod) 
        if len(bla) != 0:
            print "----"
            print bla
            
        return True
                
    def _check_conditions(self, x, break_at=15):
        # check first round conditions
        failed = []
        s = (3,7,11,19)
        for r in xrange(17):
            if r == break_at + 1:
                return failed
            
            th = self._calculate_h_until_break(x, r) # we change here to r-1
            mapping = {"a": 0, "b":1, "c":2, "d":3}
            # apply conditions:
            # round 1
            conds_round = filter(lambda x:(x[0] == r), self.conditions)
            # sort - first bits first:
            conds_round = sorted(conds_round, key=lambda x:x[1])
            for cond in conds_round:
                bit_position = cond[1]
                    
                if len(cond) == 6:
                    block_ind = cond[-1]
                    ind1 = mapping[cond[2]]
                    ind2 = mapping[cond[3]]
                    el1 = th[ind1]
                    el2 = th[ind2]
                    # we are changing el1, el1 was calculate using which block: r-2
                    if cond[4] == "same":
                        if (el1 >> bit_position) % 2 != (el2 >> bit_position) % 2:
                            #self.X_mod[block_ind] = self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32)
                            #print(cond)
                            failed.append(cond)
                    if cond[4] == "different":
                        if (el1 >> bit_position) % 2 == (el2 >> bit_position) % 2:
                            failed.append(cond)
                if len(cond) == 5:
                    block_ind = cond[-1]

                    ind1 = mapping[cond[2]]
                    el1 = th[ind1]
                    if (el1 >> bit_position) % 2 != cond[3]:
                        #self.X_mod[block_ind] = self.X_mod[block_ind] ^ 2**((bit_position+32-s[block_ind%4])%32)
                        #print(cond)
                        failed.append(cond)
                th = self._calculate_h_until_break(x, r)
                
        for r in xrange(16):
            if r + 16 == break_at:
                return failed
            th = self._calculate_h_until_break(x, r + 16)
            mapping = {"a": 0, "b":1, "c":2, "d":3}
            # round 2
            conds_round = filter(lambda x:(x[0] == r + 16), self.all_conditions)
            # sort - first bits first:
            conds_round = sorted(conds_round, key=lambda x:x[1])
            
            for cond in conds_round:
                bit_position = cond[1]
                    
                if len(cond) == 6:
                    block_ind = cond[-1]
                    ind1 = mapping[cond[2]]
                    ind2 = mapping[cond[3]]
                    el1 = th[ind1]
                    el2 = th[ind2]
                    if cond[4] == "same":
                        if (el1 >> bit_position) % 2 != (el2 >> bit_position) % 2:
                            failed.append(cond)
                if len(cond) == 5:
                    block_ind = cond[-1]
                    ind1 = mapping[cond[2]]
                    el1 = th[ind1]
                    if (el1 >> bit_position) % 2 != cond[3]:
                            failed.append(cond)
                
        return failed
                                
    def construct_collision(self, chunk):
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        self.X = X # for testing
        h = [x for x in self.h]

        self.X_mod = list(X) # deep copy
        h_mod = list(h) # deep copy
            
        bla = self.X_mod[1]
        
        #if bla < 2**31:
        #    bla += 2**31
        #    self.X_mod[1] = bla
        #else:
            #bla -= 2**31
            #bla += 1
        #    bla = (bla + 2**31) % 2**32
        #    self.X_mod[1] = bla
            
        self.X_mod[1] = (X[1] + 2**31) % 2**32
        
        #print "checking 1:"
        #test1 = struct.pack(">I", self.X_mod[1]).encode("hex")
        #print test1
                
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            
            if r == 2:
                t = h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4])
                t1 = h_mod[i] + F(h_mod[(i+1)%4], h_mod[(i+2)%4], h_mod[(i+3)%4]) 
                if (t + X[2]) % 2**32 < 2**31:
                    # t1 + x1 = t2 + X[2]
                    pass
                    #self.X_mod[2] = ((t + X[2]) % 2**32 + 2**31 - 2**28 - t1) % 2**32
                else:
                    #self.X_mod[2] = ((t + X[2]) % 2**32 - 2**31 + 1 - 2**28 - t1) % 2**32
                    pass
                #print "checking 2:"
                #test1 = struct.pack(">I", self.X_mod[2]).encode("hex")
                # I forgot what I was doing here, for now:
                #self.X_mod[2] = (X[2] + 2**31 - 2**28) % 2**32
                self.X_mod[2] = (X[2] + 2**31 - 2**28) % 2**32
            if r == 12:
                t = h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4])
                t1 = h_mod[i] + F(h_mod[(i+1)%4], h_mod[(i+2)%4], h_mod[(i+3)%4]) 
                #self.X_mod[12] = ((t + X[12]) % 2**32 - 2**16 - t1) % 2**32
                #self.X_mod[12] = ((t + X[12]) % 2**32 + 2**19 + 2**22 - t1) % 2**32
                #print "checking 12:"
                #test1 = struct.pack(">I", self.X_mod[12]).encode("hex")
                #print test1
                self.X_mod[12] = (X[12] - 2**16) % 2**32
                print "---"

            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
            h_mod[i] = leftrotate( (h_mod[i] + F(h_mod[(i+1)%4], h_mod[(i+2)%4], h_mod[(i+3)%4]) + self.X_mod[k]) % 2**32, s[r%4] )
            
            print r
            d = self.r_diff[r]
            
            # checking:
            h = self._calculate_h_until_break(X, r)
            h_mod = self._calculate_h_until_break(self.X_mod, r)
                
            actual_differences = []
            for j in range(32):
                if (h[i%4] >> j) % 2 != (h_mod[i%4] >> j) % 2:
                    if (h_mod[i%4] >> j) % 2 == 1:
                        actual_differences.append(j)
                    else:
                        actual_differences.append(-j)
                        
            print "---"
            print actual_differences
            print d
            if set(actual_differences) != set(d):
                #sys.exit("wrong in round 1: %s" % r)
                print("wrong in round 1: %s" % r)
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            
            h_old = list(h) 
            h_mod_old = list(h_mod)
            
            g = G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4])
            g1 = G(h_mod[(i+1)%4], h_mod[(i+2)%4], h_mod[(i+3)%4])
            
            c = (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999)
            c1 = (h_mod[i] + G(h_mod[(i+1)%4], h_mod[(i+2)%4], h_mod[(i+3)%4]) + self.X_mod[k] + 0x5a827999)
            
            f = (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32
            f1 = (h_mod[i] + G(h_mod[(i+1)%4], h_mod[(i+2)%4], h_mod[(i+3)%4]) + self.X_mod[k] + 0x5a827999) % 2**32
            df = self.diff_in_which_bits(f, f1)
            
            if r == 4:
                print "--"
            
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
            h_mod[i] = leftrotate( (h_mod[i] + G(h_mod[(i+1)%4], h_mod[(i+2)%4], h_mod[(i+3)%4]) + self.X_mod[k] + 0x5a827999) % 2**32, s[r%4] )
            print r
            
            
            hh = self._calculate_h_until_break(X, 19)
            hh_mod = self._calculate_h_until_break(self.X_mod, 19)
            # checking: 
            h = self._calculate_h_until_break(X, r+16)
            h_mod = self._calculate_h_until_break(self.X_mod, r+16)
            
            
            d = self.r_diff[r+16]     
            actual_differences = []
            for j in range(32):
                if (h[i%4] >> j) % 2 != (h_mod[i%4] >> j) % 2:
                    if (h_mod[i%4] >> j) % 2 == 1:
                        actual_differences.append(j)
                    else:
                        actual_differences.append(-j)
                        
            print "---"
            print actual_differences
            print d
            if set(actual_differences) != set(d):
                #sys.exit("wrong in round 2: %s" % r)
                print("wrong in round 2: %s" % r)
                return False
             

    def _add_chunk(self, chunk, is_padding_block):
        self.count += 1
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]

        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            #print "%s, %s" % (i, k)
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )    
        print "------------"
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            #print "%s, %s" % (i, k)
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4 
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def add(self, data, is_padding_block=False):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64], is_padding_block )
        return self

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        self.add( "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8), True )
        out = struct.pack("<4I", *self.h)
        X_mod = self.X_mod
        self.__init__()
        self.X_mod = X_mod
        return out
    
    def _find_conditions(self):
        # this was an attempt to find conditions for a given differential path in an automated way,
        # however, I should tackle this differently I saw later
        X_mod = [None] * 16
        X_mod[1] = [31]
        X_mod[2] = [31, -28]
        X_mod[12] = [-16]
        diff = [[], [], [], []] # don't generate using *4
        self.conditions = []
        mapping = {0: "a", 1: "b", 2: "c", 3: "d"}
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            #h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
            
            # TODO: the current implementation has a bug when there is a difference at position 0, because -0 is of course
            # rendered as 0 (and difference becomes from negative a positive)
 
            differences = [] # bit positions where we have difference at this round
            if diff[i%4] != []: # what brings h[i]
                new_bit_positions = self._help(diff[i%4], s[r%4])
                diff[i%4] = new_bit_positions # not extend, but replace
            
            if X_mod[r] != None: # what brings X[k]
                new_bit_positions = self._help(X_mod[r], s[r%4])
                diff[i%4].extend(new_bit_positions)
                           
            #print self.conditions
            print differences
            # we can try to cancel out some of the differences or introduce some new
            
            can_modify = [] # at which bit positions we can make some change (either cancel out an existing difference or make a new diff)
            can_modify.extend(diff[(i+1)%4])
            can_modify.extend(diff[(i+2)%4])
            can_modify.extend(diff[(i+3)%4])

            can_modify_x = self._help(diff[(i+1)%4], s[r%4]) # these are bit positions which can be affected (left rotation incalculated)
            can_modify_y = self._help(diff[(i+2)%4], s[r%4]) # using these we can either cancel out some of the diff[i%4] or extend diff[i%4] with new positions
            can_modify_z = self._help(diff[(i+3)%4], s[r%4])
                        
            required_diff = self.r_diff[r]
            for bit_pos in required_diff:
                # otherwise the diff in this bit will (due to +) become diff at bit_pos-1
                if bit_pos >= 0: 
                    self.conditions.append([r, bit_pos, mapping[i%4], 0])
                    differences.append(bit_pos)
                else:
                    self.conditions.append([r, -bit_pos, mapping[i%4], 1])
                    differences.append(bit_pos)
                
            #todo: currently not taking into account that 1 could turn in -1 (or the other way around) when +
            
            for bit_pos in required_diff:
                before_rot_pos = self._get_pos_before_rotation(bit_pos, s[r%4])
                if (bit_pos in diff[i%4]) or (-bit_pos in diff[i%4]): 
                    # we need to maintain the difference with F -> at this bit position F needs to be the same for F(x,y,z) and F(xx,yy,zz)
                    # if x=xx (meaning xd=False), y=yy, z=zz we need to do nothing, otherwise:
                    if (bit_pos in can_modify_x) or (-bit_pos in can_modify_x):
                        self.conditions.append([r, abs(before_rot_pos), mapping[(i+2)%4], mapping[(i+3)%4], "same"])
                    if (bit_pos in can_modify_y) or (-bit_pos in can_modify_y):
                        self.conditions.append([r, abs(before_rot_pos), mapping[(i+1)%4], 0])
                    if (bit_pos in can_modify_z) or (-bit_pos in can_modify_z):
                        self.conditions.append([r, abs(before_rot_pos), mapping[(i+1)%4], 1])
                    if -bit_pos in diff[i%4]:
                        diff[i%4].remove(-bit_pos)
                        diff[i%4].append(bit_pos)
                else:
                    changed = False
                    # add a difference in bit_pos
                    # TODO: if the same bit can be modified for example in x and y (or some other combination),
                    # we should handle this differently
                    if (bit_pos in can_modify_z) or (-bit_pos in can_modify_z):
                        if abs(bit_pos) in map(lambda x:abs(x), can_modify_x):
                            pass # this relates to the TODO above (when difference is in two F arguments) and should be much improved
                        else:
                            self.conditions.append([r, abs(before_rot_pos), mapping[(i+1)%4], 0])
                        changed = True
                    elif (bit_pos in can_modify_y) or (-bit_pos in can_modify_y):  
                        self.conditions.append([r, abs(before_rot_pos), mapping[(i+1)%4], 1])
                        changed = True
                    elif (bit_pos in can_modify_x) or (-bit_pos in can_modify_x):
                        self.conditions.append([r, abs(before_rot_pos), mapping[(i+2)%4], 0])
                        self.conditions.append([r, abs(before_rot_pos), mapping[(i+3)%4], 1])
                        changed = True
                    
                    if not changed:
                        # the difference could not be made, however it may appear due to + h[i] + X[k] (new difference can
                        # appear if 1 is propagated (when 1+1)
                        pass
                    diff[i%4].append(bit_pos)
                    
            # what if something in diff[i%4] and not in required_diff - we need to try to cancel it out
            dset = set(diff[i%4]).difference(set(required_diff))
            for bit_pos in dset:
                before_rot_pos = self._get_pos_before_rotation(bit_pos, s[r%4])
                # just copied from above for now:
                # add a difference in bit_pos
                changed = False
                # add a difference in bit_pos
                if (bit_pos in can_modify_x) or (-bit_pos in can_modify_x):
                    self.conditions.append([r, abs(before_rot_pos), mapping[(i+2)%4], 0])
                    self.conditions.append([r, abs(before_rot_pos), mapping[(i+3)%4], 1])
                    changed = True
                elif (bit_pos in can_modify_y) or (-bit_pos in can_modify_y):
                    self.conditions.append([r, abs(before_rot_pos), mapping[(i+1)%4], 1])
                    changed = True
                elif (bit_pos in can_modify_z) or (-bit_pos in can_modify_z):
                    self.conditions.append([r, abs(before_rot_pos), mapping[(i+1)%4], 0])
                    changed = True
                
                if changed:
                    if bit_pos in diff[i%4]:
                        diff[i%4].remove(bit_pos)
                    if -bit_pos in diff[i%4]:
                        diff[i%4].remove(-bit_pos)
                else:
                    #sys.exit("cannot achieve 111")
                    pass
                 
            # if these differences are to be avoided:
            for bit_pos in can_modify:
                #before_rot_pos = self._get_pos_before_rotation(bit_pos, s[r%4])
                after = self._help([bit_pos], s[r%4])[0]
                if (after in diff[i%4]) or (after in required_diff) or (-after in diff[i%4]) or (-after in required_diff):
                    continue
                else:
                    changed = False
                    if (bit_pos in diff[(i+1)%4]) or (-bit_pos in diff[(i+1)%4]):
                        self.conditions.append([r, abs(bit_pos), mapping[(i+2)%4], mapping[(i+3)%4], "same"])
                        changed = True
                    if (bit_pos in diff[(i+2)%4]) or (-bit_pos in diff[(i+2)%4]):
                        self.conditions.append([r, abs(bit_pos), mapping[(i+1)%4], 0])
                        changed = True
                    if (bit_pos in diff[(i+3)%4]) or (-bit_pos in diff[(i+3)%4]):
                        self.conditions.append([r, abs(bit_pos), mapping[(i+1)%4], 1])
                        changed = True
                    if not changed:
                        #sys.exit("cannot achieve 112")
                        pass
                    
            if set(diff[i%4]) != set(required_diff):
                #sys.exit("something is wrong")
                pass

        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            #h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4 
            #h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

            
            
