from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii
import itertools
import zlib
import random
import string
import collections
import sys
import struct
import base64
from md4 import MD4
from rc4 import RC4
import multiprocessing
#from md4test import MD4

BLOCK_SIZE = AES.block_size

def pkcs7_encode(m, block_size=16):
    l = len(m)
    val = block_size - (l % block_size) 
    m += str(bytearray([val] * val))
    return m

def get_mac(key, iv, msg):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    c0 = cipher.encrypt(msg)
    mac = c0[-16:]
    return mac

def challenge49_first_part():
    from_id = 2
    to_id = 3
    amount = 1000
    msg = "from=#{%s}&to=#{%s}&amount=#{%s}" % (from_id, to_id, amount)
    key = "1" * 16
    iv = b'\0' * BLOCK_SIZE
    mac = get_mac(key, iv, msg)

    #msg[:16] xor iv = modified_msg[:16] xor new_iv
    #new_iv = msg[:16] xor iv xor modified_msg[:16] 
    to_id = 4
    modified_msg = "from=#{%s}&to=#{%s}&amount=#{%s}" % (from_id, to_id, amount)
    new_iv = strxor(strxor(msg[:16], iv), modified_msg[:16])
    mac1 = get_mac(key, new_iv, modified_msg)

    print mac == mac1

def get_mac_fixed_iv(key, msg):
    iv = b'\0' * BLOCK_SIZE
    padded_m = pkcs7_encode(msg)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    c0 = cipher.encrypt(padded_m)
    mac = c0[-16:]
    return mac

def challenge49_second_part():
    from_id = 2
    to_id = 3
    amount = 10
    msg = "from=#{%s}&tx_list=#{%s:%s(;%s:%s)}" % (from_id, to_id, to_id, amount, amount)
    print(msg)
    print len(msg)
    key = "1" * 16
    mac1 = get_mac_fixed_iv(key, msg)
    
    # we have a message of two blocks m1 = msg[:16], m2 = msg[16:]
    # let's say msg_pad = pkcs7 padding for msg
    # mac(m1 || m2 || msg_pad || xor(m1, mac1) || m2) = mac(m1 || m2)
    padded_m = pkcs7_encode(msg)
    s = padded_m + strxor(msg[:16], mac1) + msg[16:]
    # now we know what mac has a message s and s contains more transactions than the original msg to be 
    # executed, so we are able to send a rogue request
    
    print msg
    print s
    
    smac = get_mac_fixed_iv(key, s)
    print mac1 == smac

    
def challenge50():
    m = "alert('MZA who was that?');\n"
    key = "YELLOW SUBMARINE"
    mac = get_mac_fixed_iv(key, m)
    print binascii.hexlify(mac)
    print "searching for a forged message might take some minutes"
    
    # extend it with "//" to reach the length 32 to have enough space in
    # the third block (33-48) to find a proper extension
    # "//" is added because this is a comment sign in Javascript - we can put
    # whatever (but it needs to be printable) behind and the Javascript code will still be valid
    m1 = "alert('Ayo, the Wu is back!');//" 
    # len(m1) = 32, in the third block we will use 7 characters for extension and 9 for padding
    # 9 for padding, because 9 is TAB (printable)
    forged_message = ""
    # let us denote m1 as x1||x2 (concatenation of two block - we made it long exactly two blocks)
    # let us denote extension as block x3 (7 arbitrary characters and 9 TABs)
    # let us denote m as x4||x5 (x5 is not full 16 length)
    # it holds:
    # mac(x1 || x2 || x3 || xor(mac(x1||x2||x3), x4) || x5) = mac(x4||x5)
    for extension in itertools.product(range(32, 127), repeat=7):
        extended_m1 = m1 + str(bytearray(extension))
        padded_extended_m1 = pkcs7_encode(extended_m1, 16)
        pmac = get_mac_fixed_iv(key, extended_m1)
        forged_m = padded_extended_m1 + strxor(pmac, m[:16]) + m[16:]
        mac1 = get_mac_fixed_iv(key, forged_m)
        if mac != mac1:
            print "hey, that's wrong"
            sys.exit()
        # the characters in forged_m[48:64] should be printable:
        valid = True
        for c in forged_m[48:64]:
            if (ord(c) < 32 or ord(c) > 126): # checking if printable
                valid = False
                break
        if valid:
            forged_message = forged_m
            break
    print forged_message
    mac1 = get_mac_fixed_iv(key, forged_message)
    print binascii.hexlify(mac1)
    if mac == mac1:
        print "OK"
    else:
        print "NOT OK"

def compress(d):
    c = zlib.compress(d)
    return c

cookie = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

def format_request(body):
    req = """POST / HTTP/1.1
    Host: hapless.com
    Cookie: sessionid=%s
    Content-Length: %s
    %s""" % (cookie, len(body), body)
    return req

def encrypt(d, iv, key, pad = True):
    padded_m = d
    if pad:
        padded_m = pkcs7_encode(d)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    c0 = cipher.encrypt(padded_m)
    return c0

class MaliciousClient():
    def __init__(self, cookie):
        self.charset = string.letters + string.digits + "%/+="

    def find_cookie(self):
        extensions = self.charset
        base = "Cookie: sessionid="
        constructed_cookie = base
        while len(constructed_cookie) < 44 + len(base):
            constructed_cookie = self.find_next_chars(constructed_cookie, extensions)
            print constructed_cookie
            print "====="
        return constructed_cookie

    def find_next_chars(self, partial_cookie, extensions):
        candidates = collections.defaultdict(list)
        print "---------------"
        for ext in extensions:
            body = partial_cookie + ext
            c = compress(format_request(body))
            c0 = encrypt(c, b'\0'*16, b'\1'*16)
            l = len(c0)
            # encrypt:
            b = body
            count = 1
            while True:
                # let's see how many bytes we have to add
                # to get an additional block
                # - more characters needed means better compression
                c = b[-1]
                next = chr(ord(c) + 1)
                b += next
                c = compress(format_request(b))
                c0 = encrypt(c, b'\0'*16, b'\1'*16)
                if len(c0) > l:
                    break
                count += 1
            candidates[count].append(ext)
        keys = candidates.keys()
        keys.sort()
        win = keys[-1]
        print "candidates: %s" % len(candidates[win])
        candidates_to_be_considered = candidates[win]
        if len(candidates_to_be_considered) == 1:
            return partial_cookie + candidates_to_be_considered[0]
        else:
            exts = []
            for c in candidates_to_be_considered:
                for e in self.charset:
                    exts.append(c+e)
            return self.find_next_chars(partial_cookie, exts)

def challenge51():
    client = MaliciousClient(cookie)
    cook = client.find_cookie()
    print cook
    print cookie
    if cookie in cook:
        print "ok"

def compression(chaining_value, block, hash_length):
    if len(chaining_value) != 16:
        while len(chaining_value) < 16:
            chaining_value += "3" # some stupid padding
    e = encrypt(chaining_value, b'\0'*16, block, pad=False) # block as key (as in Davies-Meyer)
    e = strxor(e, chaining_value) # as in Davies-Meyer I believe
    return e[:hash_length]

def to_bits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def from_bits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    # do not use ''.join(chars) as it would remove ' ' (for example if the last char in chars is ' ' which happens by padding when msg length is 32)
    s = ""
    for c in chars:
        s += c
    return s

def pad(m):
    m_bin = to_bits(m)
    bits_len = len(m_bin)
    bytes_len = len(m)
    rem = bits_len % 128
    nulls_len = None
    # let's use last 16 bits for message length (that would mean that m needs to be of length less than 2**16 bytes)
    # padding length at least 10 ("1" + at least one "0" + m_len in 8 bits"
    reserved_bits = 16
    if rem + reserved_bits + 2 > 128: # reserved_bits and one "1" bit and one "0" bit
        nulls_len = (128 - rem - 1) + 128 - reserved_bits # nulls to fill the last block and nulls to fill additional block (until length)
    else:
        nulls_len = 128 - rem - 1 - reserved_bits # we have to append 1, then nulls_len * 0, then length of message
    
    m_bin += [1] + nulls_len * [0]
    le = bin(bytes_len)[2:]
    if len(le[2:]) < reserved_bits:
        le = le.zfill(reserved_bits)
        le = "0b" + le
    m_bin += map(lambda x : int(x), le[2:])
    m = from_bits(m_bin)
    return m

def hash(m, initial_value, padding=True):
    # blocks are of 16-byte length (128 bits)
    # we have to add length padding, let's say we will 
    if padding:
        m = pad(m) 
    num_of_blocks = len(m) / 16
    h = initial_value
    hash_length = len(initial_value)
    for i in range(num_of_blocks):
        block = m[i*16: (i+1)*16]
        h = compression(h, block, hash_length)
    return h

def find_collision(hash_function, initial_value, padding):
    hashes = {}
    ind = 0
    charset = string.letters + string.digits + "%/+="
    # m1, m2 two different messages with the same hash
    m1 = None
    m2 = None
    while True:
        ind += 1
        m = ''.join(random.choice(charset) for x in range(16))
        h = hash_function(m, initial_value, padding)
        if h in hashes.keys():
            m1 = m
            m2 = hashes[h]
            break
        hashes[h] = m
    return m1, m2

def find_collisions(steps, iv):
    initial_value = iv
    blocks = {}
    m1, m2 = find_collision(hash, initial_value, False)
    blocks[0] = []
    blocks[0].append(m1)
    blocks[0].append(m2)
    counter = 0

    for i in xrange(steps):
        block = blocks[counter][0]
        h = hash(block, initial_value, False)
        initial_value = h
        m3, m4 = find_collision(hash, h, False)
        counter += 1
        blocks[counter] = []
        blocks[counter].append(m3)
        blocks[counter].append(m4)

    m1 = ""    
    m2 = ""    
    for i in range(steps):
        m1 += blocks[i][0]
    for i in range(10):
        m2 += blocks[i][1]
    # it should hold: hash(m1, iv) == hash(m2, iv)
    collisions = map(lambda x : x[0], blocks.values())
    
    collisions = []
    for i in range(2**steps):
        # seq will represent which (first or second) message to be taken in each block
        seq = "0" * steps         
        tail = bin(i)[2:]
        seq = seq[:-len(tail)] + tail
        c = ""
        for j in range(steps):
            c += blocks[j][int(seq[j])]
        collisions.append(c)
    # it holds: hash(collisions[i], iv) == hash(collisions[j], iv)
    return collisions

def challenge52():
    iv1 = "3" * 2
    iv2 = "3" * 3
    
    def h(message):
        # stronger hash is build by using bigger hash length - 
        # the first function outputs 2 bytes (b1 = 256**2), 
        # the second outputs 3 bytes (b2 = 256**3)
        return hash(message, iv1) + hash(message, iv2)
    
    # let's build 2**(b2/2) collisions for first (weaker) hash:
    b2 = 256**3
    # due to the birthday paradox, if we choose 1.2 * b2**(0.5) random messages, the probability
    # that there is at least one collision in these messages, is greater than 0.5.
    # we will grab b2**(0.5) messages
    # b2**(0.5) = 4096
    # we will choose 4096 messages, but not random ones, but collisions for the first (weaker) function:
    steps = 12 # 2**12 = 4096
    # ok, let's choose 8192 messages to have a greater probability:
    steps = 13
    collisions = find_collisions(steps, iv1)
    # all elements in collisions are of the length steps*16 and have the same hash
    
    d = {}
    m1 = ""
    m2 = ""
    # there is a good chance a collision for the stronger function is in collisions
    for c in collisions:
        hv = hash(c, iv2)
        if hv in d.keys():
            m1 = c
            m2 = d[hv]
            break
        d[hv] = c
    if m1 == "":
        print("collision for stronger hash not found")
        sys.exit()
    
    # now, m1 and m2 should be collision for h:
    if h(m1) == h(m2):
        print("OK")
    else:
        print("Not OK")

def find_collision_different_initial_values(hash_function, iv1, iv2):
    hashes_iv1 = {}
    hashes_iv2 = {}
    ind = 0
    charset = string.letters + string.digits + "%/+="
    # m1, m2 two different messages with the same hash
    m1 = None
    m2 = None
    while True:
        ind += 1
        m = ''.join(random.choice(charset) for x in range(16))
        h1 = hash_function(m, iv1, False)
        h2 = hash_function(m, iv2, False)
        if h1 in hashes_iv2.keys():
            m1 = m
            m2 = hashes_iv2[h1]
            break
        if h2 in hashes_iv1.keys():
            m1 = hashes_iv1[h2]
            m2 = m
            break
        hashes_iv1[h1] = m
        hashes_iv2[h2] = m
    return m1, m2

def challenge53():       
    iv1 = "3" * 2
    iv1 = "3" # use hash with output 1, otherwise it takes quite some time
    
    k = 3
    blocks = 2**k + k - 1
    charset = string.letters + string.digits + "%/+="
    msg = ''.join(random.choice(charset) for x in range(16*blocks))
    
    # let's calculate all intermediate hashes:
    H = [iv1]
    for i in range(blocks):
        H.append(hash(msg[i*16:(i+1)*16], H[i], False))
        
    # check:
    if hash(msg, iv1, False) != H[-1]:
        print "hmm44444"
        sys.exit(0)
        
    # let's find a collision with some intermediate hash for block > k
    l = random.randint(k+1, blocks-1)
    # let's say we will find a collision with intermediate hash l with some
    # block and initial state H[k]
    # H[l] is an intermediate hash after processing l blocks
    mm = None
    while True:
        m = ''.join(random.choice(charset) for x in range(16))
        if hash(m, H[k], False) == H[l]:
            mm = m
            break
        
    # now we have two messages which result in the same hash if length 
    # padding is not applied:
    if hash(mm+msg[l*16:], H[k], False) != hash(msg, iv1, False):
        print "hmmm5555"
        sys.exit(0)
            
    # now we need to construct expandable message: 
    dummy_block = "d" * 16
    collisions = []
    for i in range(k):
        dummy_h = hash(dummy_block*(2**i), H[i], False)
        # we are expanding i-th block to 2**i + 1 blocks
        # msg = block_0 + block_1 + ... + block_(k-1)
        # instead of block_i we will have 2**i + 1 blocks
        # let's have a look for i = 1
        # H[k] = hash(block_0 + block_1 + ... + block_(k-1), iv1, False)
        # we want expansion_1 of 2**1 + 1 blocks such that:
        # H[k] = hash(block_0 + expansion_1 + block_2 + ... + block_(k-1), iv1, False)
        msg_block = msg[i*16:(i+1)*16]
        some_block = None
        while True:
            m = ''.join(random.choice(charset) for x in range(16))
            h1 = hash(m, dummy_h, False)
            if h1 == H[i+1]:
                some_block = m
                break

        m2_full = dummy_block*(2**i) + some_block
        if len(m2_full) != len(dummy_block)*(2**i+1):
            print("hmmmm333")
            sys.exit(0)
        if hash(msg[:(i+1)*16], iv1, False) != hash(msg[:i*16] + m2_full, iv1, False):
            print("hmmmm222")
            sys.exit(0)
        collisions.append(m2_full)
        #iv1 = hash(m1, iv1, False)
    # if we concatenate all m2_full messages we get the following number of blocks:
    #  (2**0 + 1) + (2**1 + 1) + ... + (2**(k-1) + 1) = 2**k - 1 + k
    if hash(msg[:k*16]+mm+msg[l*16:], iv1, False) != hash(msg, iv1, False):
        print "hmm1111"
        sys.exit(0)
    # we are now able to expand first k blocks
    # we need length of l-1 blocks so that:
    # expanded message + mm + msg[l*16:] will be the same length as msg
    # so expanded message needs to be of l-1 blocks
    # thus we need to expand first k blocks by l-1-k blocks 
    # we can expand first block by 2**0 blocks, the second block by 2**1 blocks, the third by 2**2 blocks ...
    bl = list(bin(l-k-1)[2:]) # this tells if we need to take an expanded block or not
    final_msg = ""
    while len(bl) < k:
        bl.insert(0, "0")
    bl.reverse()
    for i in range(k):
        if bl[i] == "1":
            final_msg += collisions[i]
        else:
            final_msg += msg[i*16:(i+1)*16]
    final_msg += mm + msg[l*16:]
    if hash(msg, iv1) != hash(final_msg, iv1):
        print "not OK"
    else:
        print "OK"
    
def challenge54():
    iv1 = "33"
    k = 8
    hs = collections.defaultdict(list)
    msgs = collections.defaultdict(list)
    charset = string.letters + string.digits + "%/+="
    while len(hs[0]) < 2**k:
        b = ''.join(random.choice(charset) for x in range(16))
        h = hash(b, iv1, False)
        if h not in hs[0]:
            hs[0].append(h)
            msgs[0].append(b)
    # build a diamond structure:
    for j in range(k):
        for i in range(0, 2**(k-j), 2):
            m1, m2 = find_collision_different_initial_values(hash, hs[j][i], hs[j][i+1])
            hs[j+1].append(hash(m1, hs[j][i], False))
            msgs[j+1].append(m1)
            msgs[j+1].append(m2)
    # check the structure:
    b = random.randint(0, 2**k - 1)
    #print 0, b
    m = msgs[0][b]
    for i in range(0, k):
        #print i+1, b
        m += msgs[i+1][b]
        # now m gives hash: h[i+1][b/2]
        b = b/2
    if hash(m, iv1, False) != hs[k][0]:
        print "hmmmm1111"
        sys.exit(0)
    H = hs[k][0]
    # we chose H which will be hash of our predicted message
    # we now wait the game to be finished - the result turns out to be 17:11
    # now we have to produce message which will contain block "it will be 17:11" and some suffix, 
    # and it will hash to H
    m = "it will be 17:11" # proper length is important
    # let us find a link_block for which hash(m + link_block, iv1, False) = some intermediate hash from the diamond structure:
    link_block = None
    ind = None
    while True:
        b = ''.join(random.choice(charset) for x in range(16))
        h = hash(m + b, iv1, False)
        # let us cheat a little bit and check only the hashes 
        # which are the result of two-block messages - hs[1]
        # this is to avoid having to build expandable messages - we will find a collision of
        # two-block message (m + link_block) with some value with h[1]
        # if we would find collision of m+link_block with some of the intermediate
        # hashes in other layers (hs[2], hs[3] ... ) we would need to expand (m + link_block) as
        # in the previous challenge
        if h in hs[1]:
            link_block = b
            ind = hs[1].index(h)
            break
    suffix = ""
    b = ind
    for i in range(1, k):
        #print i+1, b
        suffix += msgs[i+1][b]
        # now m gives hash: h[i+1][b/2]
        b = b/2

    if hash(m+link_block+suffix, iv1, False) == H:
        print "message"
        print m+link_block+suffix 
        print "contains the predicted result and has the hash that we submitted before the game"
    else:
        print "not OK"

def challenge55():
    md = MD4()
    # these are the two messages (given in a Wang's paper) that have the 
    # same hash (written in little endian)
    #h = "4d7a9c8356cb927ab9d5a57857a7a5eede748a3cdcc366b3b683a0203b2a5d9fc69d71b3f9e99198d79f805ea63bb2e845dd8e3197e31fe52794bf08b9e8c3e9"
    #h = "4d7a9c83d6cb927a29d5a57857a7a5eede748a3cdcc366b3b683a0203b2a5d9fc69d71b3f9e99198d79f805ea63bb2e845dc8e3197e31fe52794bf08b9e8c3e9"
    #m = h.decode("hex")

    # convert to big endian before packing into string:
    # (split into 8 4-bytes blocks and then invert the order of bytes in each block)
    #b = struct.unpack("<16I", m)
    #m = struct.pack(">16I", *b)
    
    print "Wang's paper reports that 4 to 64 randomly selected messages are needed to find a collision;"
    print "with this implementation a few thousands randomly selected messages are needed (it takes some minutes)"
    print "to find a collision - could be because not all multi-step modifications have been applied"
    print ""
    
    charset = string.letters + string.digits + "%/+=" 
    for i in range(10000):
        m = ''.join(random.choice(charset) for x in range(64)) 
        #m = "PyxsBFALuSQW0AsCRKx7wXvRRyKIOIMg1v3hN+dlguuqGnKP1Y=BYo/gR1JHp86="
        #m = "AaUjDhPG6n6acvWmRecqqQ5IDlI0+Klkw9oe6rzDQ=b1/7rtQB2rE=VrxEC2aRhK"
        
        # fails in i = 35 (even all conditions are met, the steps 32 and 33 might fail)
        #m = "wJKsvK3V1Ypyi7U5I=Wqbe2VJRne29l/Q9LADne=YJg65DBrwTuPj7WP=oLK6q/W"
        #m = "l13YLL0oC/rnykdK%i5q%5abUwLNvleCPv6hspmmDPoSG4kX0W9SI2qlsYpJZBb6"
        #m = "M/LxOqd9KpzNY4G%bh9dT%kTGLrpk9wCU4hi+4/K3n=9yufGrqqCD8ULG9rcBh91"
        #m = "+JiumjNHGtbVX886=0qnZSZYx/uX%MHUO8q0Aq0NWa%Zi8nQ=hwrh+5X5udJyNhy"
        
        #h = "4b67208753178a6617a95fb685448610209732e8abe97a8c5bc7d9a615136f314d475b027ff19f881befb76080eb382e169f30e1b6e9347edd17890badbfeae3"
        #m = h.decode("hex")
        #b = struct.unpack("<16I", m)
        #m = struct.pack(">16I", *b)
        
        #ok = md.modify_message(m)
        #print ok
        
        #md = MD4()
        #md.add(m)
        #d = md.finish()
        #hash1 = d.encode("hex")
        
        #h1 = "4b672087d3178a6687a95fb685448610209732e8abe97a8c5bc7d9a615136f314d475b027ff19f881befb76080eb382e169e30e1b6e9347edd17890badbfeae3"
        #m1 = h1.decode("hex")
        #b1 = struct.unpack("<16I", m1)
        #m1 = struct.pack(">16I", *b1)
        
        #md = MD4()
        #md.add(m1)
        #d = md.finish()
        #hash2 = d.encode("hex")
        
        #print hash1
        #print hash2
        
        # collisions are constructed for example for:
        #m = "hMJI75MIPD2ib4SjeJKrMiOrjWD59/CdhM8mUuWC81Fd1nQXrnaQs44P060kCbAh"
        #m = "4MuGCKvYPnlmdnhAab1JF=J4l7/YSMw30WJvY4izj%fgwXuTgADMLptYTBn9Gdww"

        #m = "\xff" * 8 * 8
        #ms = struct.unpack("<16I", m) # m_0, m_1, ..., m_15
        # m_0 - "1234", m_1 - "5678", m_3 - "1234", m_4 - "5678" ...
    
        # modify message to be of the format for which we can construct collision
        ok = md.modify_message(m)
        if not ok:
            continue
        x_mod = md.X_mod[:16]
        # x_mod has been constructed using little endian, so consider this when packing into string:         
        
        l1 = map(lambda x : struct.pack("<I", x), x_mod)
        m_mod = "".join(l1)
    
        md = MD4()
        md.add(m_mod)
        d = md.finish()
        hash1 = d.encode("hex")
    
        # construct collision:
        success = md.construct_collision(m_mod)
        if success == False: # it could be None
            continue
        x_coll = md.X_mod[:16]
        # x_mod has been constructed using little endian, so consider this when packing into string:
    
        l1 = map(lambda x : struct.pack("<I", x), x_coll)
        x_coll = "".join(l1)

        md1 = MD4()
        md1.add(x_coll)
        d = md1.finish()
        hash2 = d.encode("hex")
        for i in range(25, 38):
            break
            print "======"
            # i = 35 ... b_9
            # i = 36 ... a_10
            # i = 37 ... d_10
            t = md._calculate_h_until_break(md.X[:16], i)
            if i == 35:
                print "---"
                print t
            t1 = md._calculate_h_until_break(md.X_mod[:16], i)
            if t != t1:
                print i
                print t
                print t1
                da, db, dd = None, None, None
                if i == 35:
                    db = t1[1] - t[1]
                    print db
                if i == 36:
                    da = t1[0] - t[0]
                    print da
                if i == 37:
                    dd = t1[3] - t[3]
                    print dd
        
        print hash1
        print hash2
        if hash1 == hash2:
            print "Hash collision!"
            print "The following two messages have the same hash:" 
            print m_mod
            print x_coll
            break
        else:
            print "Not OK"
            #md.update(m_mod)
            
def challenge56():
    key = 'Key'
    p = "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"
    plaintext = base64.b64decode(p)
    print "This may take some hours..."
    
    charset = string.letters + string.digits + "%/+=" 
    
    def convert_key(s):
        return [ord(c) for c in s]
    
    import collections
    import operator
    
    def worker(q1, q2, z_i, exp, ptext):
        # 15 (Z_16) has bias towards 240 (Gupta), also towards 0 and 16
        # 31 (Z_32) has bias towards 224, also 0 and 32
        # 49 (Z_50) has bias towards 0, also 50
        counter1 = collections.defaultdict(int)
        key_counter1 = collections.defaultdict(int)
        # 2**17 seems to be enough for 15 (240 wins)
        # 2**19: 224 twice on the second place, three times on first
        for _ in range(2**exp): # 21 was here, 24 takes too long
            key = ''.join(random.choice(charset) for _ in range(16)) 
            key1 = convert_key(key)
            keystream = RC4(key1)
            ctext = []
            for ind, p in enumerate(ptext):
                k = keystream.next()
                ci = ord(p) ^ k
                ctext.append(ci)
                if ind == z_i:
                    key_counter1[k] += 1
                    break
            counter1[ctext[z_i]] += 1
            #return counter1
        q1.put(counter1)
        q2.put(key_counter1)
    
    solution = ""
    for ind, _ in enumerate(plaintext):
        
        q1 = multiprocessing.Queue()
        q2 = multiprocessing.Queue()
        
        z_i, exp, k1 = None, None, None
        if ind < 16:
            ptext = (15-ind) * "a" + plaintext
            z_i = 15
            exp = 19
            k1 = 240
        else:
            ptext = (31-ind) * "a" + plaintext
            z_i = 31
            exp = 20
            k1 = 224
        jobs = []
        num_of_processes = 8
        for i in range(num_of_processes):
            p = multiprocessing.Process(target=worker, args=(q1, q2, z_i, exp, ptext))
            jobs.append(p)
            p.start() 
        counter_all = collections.defaultdict(int)
        key_counter_all = collections.defaultdict(int)
        for _ in range(num_of_processes):
            c = q1.get()
            for k, v in c.iteritems():
                counter_all[k] += v
        for _ in range(num_of_processes):
            c = q2.get()
            for k, v in c.iteritems():
                key_counter_all[k] += v
        
        sorted_counter = sorted(counter_all.items(), key=operator.itemgetter(1))
        #sorted_key_counter = sorted(key_counter_all.items(), key=operator.itemgetter(1))
        #print sorted_counter[-7:]
        #print sorted_key_counter[-7:]
        
        t = chr(sorted_counter[-1][0] ^ k1)
        solution += t
        print solution
        
        
    

#challenge49_first_part()
#challenge49_second_part()
challenge50()
#challenge51()
#challenge52()
#challenge53()
#challenge54()
#challenge55()
#challenge56()




