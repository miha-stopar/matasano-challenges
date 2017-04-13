from Crypto.Util.number import *

class Oracle():
    def __init__(self, rsa, B, noterm, shortpad):
        self.rsa = rsa
        self.B = B
        self.noterm = noterm
        self.shortpad = shortpad
        self.mmin = self._get_min(B)
        self.mmax = self._get_max(B)
    
    def call(self, c, p=None):
        m, conformant = self.rsa.decrypt(c, self.mmin, self.mmax)
        if not conformant:
            return conformant
        else:
            pass
        sep = m.find(bchr(0x00), 2)
        termination_available = sep >= 2
        valid_padding = (sep >= 10 or sep == -1)

        if not self.noterm:
            if not termination_available:
                #sys.exit(1)
                # debugging:
                #print("not valid padding - no zero after padding string")
                return False
        if not self.shortpad:
            if not valid_padding:
                #sys.exit(1)
                # debugging:
                #print("not valid padding - there is a zero in a non-zero padding string")
                return False
        return True    

    def _get_min(self, B):
        if self.shortpad:
            return 2*B
        else:
            m = 2*B
            # padding string is at least 8 bytes long:
            for i in range(1, 9):
                m += pow(256, 128-2-i)
        return m

    def _get_max(self, B, plaintext_len=0):
        if self.noterm:
            return 3*B - 1
        else:
            m = 2*B
            for i in range(0, 126):
                m += 255*pow(256, i)
            # if plaintext_len is not given (it is 0 by default) this is still ok, because
            # 0 appears somewhere, at least in the last byte
            m -= 255*pow(256, plaintext_len) # there is 0 marking the end of padding block
        return m
