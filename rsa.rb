require 'openssl'
require_relative 'util'

class RSA
    def initialize(prime_size=1024)
         p = OpenSSL::BN::generate_prime(prime_size)
         q = OpenSSL::BN::generate_prime(prime_size)

	 #p = OpenSSL::BN::generate_prime(100) # small numbers for testing - however it won't work if the message will be greater than n
         #q = OpenSSL::BN::generate_prime(100)
         @n = p*q
	 #puts p.to_i.to_s(2).length
	 #puts q.to_i.to_s(2).length
	 #puts @n.to_i.to_s(2).length
         et = (p-1)*(q-1) # number of elements in Z_n*
         @e = 3 # gcd(e, et) should be 1
         @d = Util.invmod(et, @e) 
         # public key: [e, n]
         # private key: [d, n]
    end 

    def n
	return @n
    end

    def e
	return @e
    end

    def encrypt(m)
	num = m.unpack("H*").join
  	num = num.to_i(16)
 	#c = num.to_bn.mod_exp(@e, @n)
	c = num**@e % @n
	c
    end

    def decrypt(c)
 	p = c.to_bn.mod_exp(@d, @n)
	#p = c**@d % @n # seems that d is too big
	p = p.to_s(16)
	p = [p].pack("H*")
	return p
    end

    def sign(m)
	num = m.unpack("H*").join
  	num = num.to_i(16)
 	c = num.to_bn.mod_exp(@d, @n)
	c
    end

    def verify(signature, hash)
 	p = signature.to_bn.mod_exp(@e, @n)
	p = p.to_s(16)
	p = [p].pack("H*")
	pattern = '(?<=\xff\xff\xff\x00).*'
	reg = Regexp.new(pattern, Regexp::MULTILINE, 'n')
	m = reg.match(p)[0]
	m = m[14..-1] # asn.1
	hash_length = m[0].ord
	extracted_hash = m[1..hash_length]
	if extracted_hash == hash
	    return true
	else
	    return false
	end
    end

end
