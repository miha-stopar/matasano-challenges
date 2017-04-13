require 'digest/sha1'
require 'openssl'
require_relative 'rsa'
require_relative 'util'

class Oracle
    def initialize()
        @rsa = RSA.new
    end

    def decrypt(c)
	return @rsa.decrypt(c)
    end
    
    def get_parameters()
	return @rsa.e, @rsa.n
    end
    
    def prepare_some_ciphertext()
	c = @rsa.encrypt('hello1')
	return c
    end
end

def challenge41()
    oracle = Oracle.new
    e, n = oracle.get_parameters()
    c = oracle.prepare_some_ciphertext()
    s = 7
    c_new = (((s ** e) % n) * c) % n
    p_new = oracle.decrypt(c_new)
    p_new_int = p_new.unpack("H*").join.to_i(16)
    s_inv = Util.invmod(n, s)
    puts [((p_new_int * s_inv % n)).to_s(16)].pack("H*")
end

def pkcs1(m)
    # 0.chr * 14 should be replaced by proper asn.1
    padded_m = 0.chr + 1.chr + 255.chr * 346 + 0.chr + 0.chr * 14 + m.length.chr + m
end

def challenge42()
    m = 'hi mom'
    h = Digest::SHA1.digest(m)
    padded_h = pkcs1(h)
    rsa = RSA.new
    signature = rsa.sign(padded_h)
    puts rsa.verify(signature, h)
    #forged_m = 0.chr + 1.chr + 255.chr * 87 + 0.chr + 0.chr * 14 + h.length.chr + h + 0.chr * 259
    forged_m = 0.chr + 1.chr + 255.chr * 3 + 0.chr + 0.chr * 14 + h.length.chr + h + 0.chr * 343
    puts forged_m
    puts forged_m.unpack("H*")[0]
    a = forged_m.unpack("H*")[0].to_i(16)
    puts a
    max = 0.chr + 1.chr + 255.chr * 3 + 0.chr + 0.chr * 14 + h.length.chr + h + 255.chr * 343
    max = max.unpack("H*")[0].to_i(16)

    t = Util.nthroot(3, a) # nthroot calculates slightly smaller than the actual value, it holds t**3 < a
    t += 1 # now it should be t**3 > a
    raise 'the number not big enough' if t**3 < a
    raise 'the number is too big' if t**3 > max
    puts t
    puts rsa.verify(t, h)
end

def challenge43()
    p = '800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1'
    q = 'f4f47f05794b256174bba6e9b396a7707e563c5b'
    g = '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291'
    p = p.to_i(16)
    q = q.to_i(16)
    g = g.to_i(16)

    m = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

    h = Digest::SHA1.hexdigest(m)
    h_num = h.hex

    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    k = 0
    for i in (0..2**16)
        r_t = g.to_bn.mod_exp(i, p) % q
        if r_t == r
	    k = i 
	    puts 'k found!'
 	    break
        end 
    end
    puts k
    #k_inv = Util.invmod(q, k)
    #s = k_inv * (h_num + a * r) % q
    r_inv = Util.invmod(q, r)
    a = ((s * k - h_num) * r_inv) % q
    puts a
    puts a.to_s(16)
    check = Digest::SHA1.hexdigest(a.to_s(16))
    puts check
end

def challenge44()
    p = '800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1'
    q = 'f4f47f05794b256174bba6e9b396a7707e563c5b'
    g = '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291'
    p = p.to_i(16)
    q = q.to_i(16)
    g = g.to_i(16)

    y = '2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821'
    y = y.to_i(16)

    file = File.open('44.txt', 'r')
    # just found one repeated r, for other pairs it would be the same:
    rs = []
    first = {}
    repeated = {}
    firstExtracted = false
    data = first
    repeatFound = false
    file.each_line { |line|  
	    if line[0..1] == 's:'
	        data['s'] = line[3..-2].to_i
	    end
	    if line[0..1] == 'r:'
	        data['r'] = line[3..-2].to_i
		if firstExtracted and data['r'] == first['r']
		    repeatFound = true
		end
	    end
	    if line[0..1] == 'm:'
	        data['hash'] = line[3..-2]
		firstExtracted = true
		data = repeated 
		if repeatFound
		    break
		end
	    end
    }
    puts first
    puts repeated
    sdiff = first['s'] - repeated['s']
    sdiff_inv = Util.invmod(q, sdiff)
    k = ((first['hash'].hex - repeated['hash'].hex) * sdiff_inv) % q

    r_inv = Util.invmod(q, first['r'])
    a = ((first['s'] * k - first['hash'].hex) * r_inv) % q
    h = Digest::SHA1.hexdigest(a.to_s(16))
    puts h

end

def challenge45()
    p = '800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1'
    q = 'f4f47f05794b256174bba6e9b396a7707e563c5b'
    g = 0
    p = p.to_i(16)
    q = q.to_i(16)
    g = p+1

    bigA = '2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821'

    m = 'foo'
    h = Digest::SHA1.hexdigest(m)
    h_num = h.hex
    a = rand(q)
    bigA = g.to_bn.mod_exp(a, p)
    k = rand(q)
    #r = g.to_bn.mod_exp(k, p) % q

    # forge signature - only with knowing public key bigA:
    r = bigA.to_bn.mod_exp(h_num, p) % q
    h_num_inv = Util.invmod(q, h_num)
    s = (r * h_num_inv) % q

    #k_inv = Util.invmod(q, k)
    #s = k_inv * (h_num + a * r) % q

    # verify:
    s_inv = Util.invmod(q, s)
    # when calculating c both factors are calculated modulo p and then once again the product is modulo p, this is necessary only because otherwise the numbers are too big
    c = ((g.to_bn.mod_exp((s_inv * h_num) % q, p) * bigA.to_bn.mod_exp((r * s_inv) % q, p)) % p) % q
    if c == r
	puts 'signature valid'
    else
	puts 'signature NOT valid'
    end
   
end

class RsaOracle
    def initialize()
        @rsa = RSA.new
    end

    def get_parameters()
	return @rsa.e, @rsa.n
    end

    def isOdd(c)
        m = @rsa.decrypt(c) 
	num = m.unpack("H*").join.to_i(16)
        if num % 2 == 0
	    return false
	else
	    return true
	end 
    end
end

def challenge46()
  s = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
  m = s.unpack('m0')[0]

  m = "That\'s why I found you don\'t play around with the Funky Cold Medina"

  oracle = RsaOracle.new
  #encrypt:
  puts '________________________'
  num = m.unpack("H*").join.to_i(16)
  puts num
  puts '________________________'
  e, n = oracle.get_parameters()
  puts '----'
  puts n
  c = num.to_bn.mod_exp(e, n)

  i = 1
  max = n
  min = 0
  while true do
    c1 = ((2**i)**e * c) % n
    isOdd = oracle.isOdd(c1)
    if isOdd
      min = max - (max-min).to_i/2 # to_i used because dividing OpenSSL:BN returns an array with also a remainder
      #if min % 2 == 0 and (max-min) % 2 == 0 and min != max
      if min != max
	if ((min * (2**i)) % n) % 2 != 1
	  min = min + 1
        end
      end
    else
      max = min + (max-min).to_i/2
      if max != min
	if ((max * (2**i)) % n) % 2 == 1
	  max = max - 1 
        end
      end
    end
    if min == max
      break 
    end
    i += 1
  end
  puts min
  puts [min.to_s(16)].pack("H*")
  #puts [max.to_s(16)].pack("H*")
end

class RsaOracle1
    def initialize()
        @rsa = RSA.new(128)
    end

    def get_parameters()
	return @rsa.e, @rsa.n
    end

    def isPKCSconforming(c)
        m = @rsa.decrypt(c) 
        if m.length == 31 and m[0] == 2.chr # the first 0.chr does not have effect
	    return true
	else
	    return false
	end 
    end

    def prepare_some_ciphertext()
    	m = "kick it, CC"
        k = @rsa.n.to_i.to_s(16).length / 2 # number of bytes of n
	d = k - m.length - 3 # how long should be random padding string 
	padded_m = 0.chr + 2.chr + 11.chr * d + 0.chr + m # should be random instead of "11" * d
	c = @rsa.encrypt(padded_m)
	conforming = isPKCSconforming(c)
	return c, padded_m
    end
end

def find_bounds(start, round, e, n, c, bigB, oracle, padded_m_num, a, b)
    puts "++++++++++++++++++++++++++++++++++++++++++++"
    puts start
    for i in (start..start+100000)
        c1 = (i**e * c) % n
	conforming = oracle.isPKCSconforming(c1)
	puts i*a
	puts i*padded_m_num
	puts i*b
	puts n
	puts "------"
	puts i*a / n
	puts i*padded_m_num / n
	puts i*b / n
	puts "------"

	h = i * padded_m_num
        f = (i * padded_m_num) % n
        #m = [f.to_s(16)].pack("H*")
	#if m.length == 31 and m[0] == 2.chr # the first 0.chr does not have effect
	#if m[1] == 2.chr # the first 0.chr does not have effect
	#    puts "==========="
	#    puts i
	#    puts "==========="
	#else
	#end 
	if f > 2*bigB and f < 3*bigB
	    puts "==========="
	    puts i
	    puts "==========="
	else
	end
        
	if conforming
	    puts "founddddddddddddd, this is round " + round.to_s
	    puts i
	    #puts i * c
	    #puts n + 2*bigB
	    #puts n + 3*bigB
	    min = ((round+1)*n+2*bigB)/i
	    max = ((round+1)*n+3*bigB)/i
	    #puts "--------------"
	    puts min
	    puts max
	    #puts "--------------"
	    h = i * padded_m_num
	    f = (i * padded_m_num) % n

	    if h > (round+1)*n and h < (round+2)*n
	    else
		#puts "something wrong 1"
	    	if h > (round+2)*n and h < (round+3)*n
		    puts "at least this"
		end
	    end

	    if f > 2*bigB and f < 3*bigB
	    else
		puts "something wrong 2"
	    end
	    return min, max, i
	end
    end

end

def find_bounds1(start, round, e, n, c, bigB, oracle, padded_m_num, a, b)
    if round == 0
        for i in (start..start+100000)
            c1 = (i**e * c) % n
	    conforming = oracle.isPKCSconforming(c1)
	    if conforming
		puts "found! s is " + i.to_s + "; round: " + round.to_s
		return 0, 0, i
	    end
        end
    else
	start_r = 2 * (b * start - 2 * bigB) / n
	puts "+++"
	puts start
	puts start_r
        for r_i in (start_r..start_r+1000)
	    b1 = (2*bigB + r_i * n)/b
	    b2 = (3*bigB + r_i * n)/a
	    t1 = b1 * padded_m_num
	    t2 = b2 * padded_m_num
	    #puts b1
	    #puts b2
	    #puts "-----------------------"
	    #puts 2 * bigB + r_i * n
	    #puts ((2 * bigB + r_i * n)/a) * padded_m_num
	    #puts t1
	    #puts t2
	    #puts ((3 * bigB + r_i * n)/b) * padded_m_num
	    #puts 3 * bigB + r_i * n
	    #puts "-----------------------"

	    if t1 * padded_m_num < 2 * bigB + r_i * n or t1 * padded_m_num > 3 * bigB + r_i * n
	        puts "wrong 1"
	    end
	    if t2 * padded_m_num < 2 * bigB + r_i * n or t2 * padded_m_num > 3 * bigB + r_i * n
	        puts "wrong 2"
	    end

  	    for s_i in (b1..b2-1)
              	    c1 = (s_i**e * c) % n
	    	    conforming = oracle.isPKCSconforming(c1)
	    	    if conforming
   		        #puts s_i*a
		        #puts s_i*padded_m_num
		        #puts s_i*b
		        #puts n
		        #puts "------"
		        #puts s_i*a / n
		        #puts s_i*padded_m_num / n
		        #puts s_i*b / n
		        #puts "------"
		        puts "found! s is " + s_i.to_s + "; round: " + round.to_s
	    	        min = ((r_i-1)*n + 2*bigB)/s_i
	    	        max = ((r_i-1)*n + 3*bigB-1)/s_i

		        h = s_i * padded_m_num
	                f = (s_i * padded_m_num) % n

		        puts "================="
		        puts r_i
		        puts "---"
		        puts (r_i-1)*n
		        puts r_i*n
		        puts h
		        #puts (r_i+1)*n
		        puts "================="

	      	        if h > r_i*n and h < (r_i+1)*n
	    	        else
		  	    #puts "something wrong 1"
	    		    if h > (r_i+1)*n and h < (r_i+2)*n
		    	        puts "at least this"
			    end
	    		end

	    	        if f > 2*bigB and f < 3*bigB
	    	        else
		    	    puts "something wrong 2"
	    		end

		        return min, max, s_i
   		    end
	    end
        end
    end
end

def get_r(s_i, a, b, n, bigB)
    r_min = s_i*a/n
    r_max = s_i*b/n
    if s_i*a > s_i*a/n * n + 3 * bigB
        #puts "r is bigger than s_i*a/n"
        r_min = s_i*a/n + 1
    end
    if s_i*b < s_i*b/n * n + 2 * bigB
        #puts "r is less than s_i*b/n"
        r_max = s_i*b/n - 1
    end
    if r_min == r_max
        return r_min
    else
        return nil
    end
end

def find_bounds2(start, round, e, n, c, bigB, oracle, padded_m_num, a, b, nice_multipliers)
    for s_i in (start..start+100000)
        c1 = (s_i**e * c) % n
	r = get_r(s_i, a, b, n, bigB)
        if r != nil
       	    conforming = oracle.isPKCSconforming(c1)
	    if conforming
		puts "found!! s_i - start: " + (s_i-start).to_s
		puts "s_i: " + s_i.to_s
		min = (r*n + 2*bigB) / s_i
		max = (r*n + 3*bigB - 1) / s_i
		return min, max, s_i, r
	    end
	end
    end
end

def get_verifying(p, n, bigB)
    l = []
    for i in (2..1000000)
	m = p * i % n
	if m > 2*bigB and m < 3*bigB 
	    r = p*i/n
	    l.push([i, r])
	end
    end
    return l
end

def find_cands(min, max, n, bigB)
    r = 1
    cands = []
    puts min
    puts max
    while true
        #atleast1 = 1 + ((r-1)*n + 3*bigB)/min
        #atleast2 = 1 + (r*n + 2*bigB)/max
        atleast1 = ((r-1)*n + 3*bigB)/min
        atleast2 = (r*n + 2*bigB)/max

        atmost1 = ((r+1)*n + 2*bigB)/max
        atmost2 = (r*n + 3*bigB)/min

    	atleast = [atleast1, atleast2].max  
    	atmost = [atmost1, atmost2].min
	puts "====="
	puts atleast
	puts atmost
        if atleast > atmost
	    return cands
	end
	cands.push([atleast, atmost, r])
	r += 1
    end
end

def challenge47()
    oracle = RsaOracle1.new
    e, n = oracle.get_parameters()
    c, padded_m = oracle.prepare_some_ciphertext()
    k = n.to_i.to_s(16).length / 2 # number of bytes of n
    bigB = 256**(k-2)
    puts "================="
    puts n
    padded_m_num = padded_m.unpack("H*").join.to_i(16)
    puts padded_m_num
    #verifying = get_verifying(padded_m_num, n, bigB)
    #p verifying

    d1 = 0
    d2 = 0

    a = 2 * bigB
    b = 3 * bigB - 1
    puts a
    puts b
    puts "================="

    #puts (n+2*bigB)/(3*bigB) # start
    #puts (n+3*bigB)/(2*bigB) # stop
    puts "-----"
    puts n+2*bigB
    puts n+3*bigB

    start = 2
    #start = n/bigB
    nice_multipliers = []
    min = a
    max = b
    for i in (0..100)
	#min, max, s = find_bounds(start, i, e, n, c, bigB, oracle, padded_m_num, a, b)
	#min, max, start_new = find_bounds1(start, i, e, n, c, bigB, oracle, padded_m_num, a, b)
	puts "round: " + i.to_s
	puts start
	puts "-----------------------------------"
	#cands = find_cands(min, max, n, bigB)
  	#p cands

	min, max, start_new, r = find_bounds2(start, i, e, n, c, bigB, oracle, padded_m_num, a, b, nice_multipliers)

	start = (10*2048*r * n + 2*bigB)/a
	#start = start_new + 1
	if i > -1
	    if min > a
		puts "min improved"
		a = min
	    end
	    if max < b
		puts "max improved"
		b = max
	    end
	    #puts min
	    #puts max
	    nd1 = b - padded_m_num
	    nd2 = padded_m_num - a
	    puts nd1
	    puts nd2
	    if b-a <2
	        break
	    end
	    puts "------------"
            if d1 != 0 and d2 != 0
	        if nd1 < d1 and nd2 < d2
	        else
		    "diff is not getting smaller"
	        end
	        d1 = nd1
	        d2 = nd2
	    end
	end
	#start = s + 1
    end
    
end

#challenge41()
#challenge42()
#challenge43()
#challenge44()
#challenge45()
#challenge46()
challenge47()



