require 'securerandom'
require 'openssl'
require 'digest'
require 'digest/sha1'
require_relative 'rsa'
require_relative 'util'

def challenge33()
    #p = 37
    # don't split p into lines simply with enter and single quotes - it will read only the first line
    p = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
    puts p.to_i(16)
    #puts [p].pack("H*")
    p = p.to_i(16)
    #return
    g = 2
    a = SecureRandom.random_number(p)
    puts "a: " + a.to_s
    # bigA = g**a % p # this don't work for big p
    bigA = g.to_bn.mod_exp(a, p)
    puts "A: " + bigA.to_s
    b = SecureRandom.random_number(p)
    puts "b: " + b.to_s
    # bigB = g**b % p # this won't work for big p
    bigB = g.to_bn.mod_exp(b, p)
    puts "B: " + bigB.to_s
    s1 = bigB.to_bn.mod_exp(a, p)
    s2 = bigA.to_bn.mod_exp(b, p)
    puts s1 == s2
    puts "shared key: " + s2.to_s
end

class Some
    attr_accessor :p
    attr_accessor :g
    attr_accessor :secret_num
    attr_accessor :bigA
    attr_accessor :bigB
    attr_accessor :shared_key
    
    def encrypt(msg)
	cipher = OpenSSL::Cipher.new("AES-128-CBC")
        iv = cipher.random_iv
	h = shared_key.to_s(16)
    	key = Digest::SHA1.digest(shared_key.to_s)[0..15]
	ciphertext = Util.cbc_encrypt(msg, iv, key)
	return ciphertext + iv
    end

   def decrypt(msgiv)
        iv = msgiv[-16..-1]
	msg = msgiv[0..-17]
	h = shared_key.to_s(16)
    	key = Digest::SHA1.digest(shared_key.to_s)[0..15]
	plaintext = Util.cbc_decrypt(msg, iv, key)
	return plaintext
    end
end

class Network
    def send(sender, receiver, p, g, bigA, bigB)
        receiver.p = p
        receiver.g = g
        receiver.bigA = bigA
        receiver.bigB = bigB
    end
end

def challenge34()
    # alice's side
    alice = Some.new
    p = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
    p = p.to_i(16)
    g = 2
    a = SecureRandom.random_number(p)
    bigA = g.to_bn.mod_exp(a, p)
    alice.p = p
    alice.g = g
    alice.secret_num = a
    alice.bigA = bigA
    bob = Some.new
    network = Network.new
    network.send(alice, bob, p, g, bigA, nil)

    # bob's side
    b = SecureRandom.random_number(p)
    bigB = g.to_bn.mod_exp(b, p)
    bob.secret_num = b
    bob.shared_key = bob.bigA.to_bn.mod_exp(b, p)
    network.send(bob, alice, p, g, bigA, bigB)

    # alice's side
    alice.shared_key = alice.bigB.to_bn.mod_exp(a, p)
    ciphertext = alice.encrypt("hello")

    puts bob.decrypt(ciphertext)

    # MITM parameter injection attack:
    a = SecureRandom.random_number(p)
    bigA = g.to_bn.mod_exp(a, p)
    alice.p = p
    alice.g = g
    alice.secret_num = a
    alice.bigA = bigA
    mitm = Some.new
    network = Network.new
    network.send(alice, mitm, p, g, bigA, nil)

    # mitm's side
    bigA = p
    network.send(mitm, bob, p, g, bigA, nil)

    # bob's side
    b = SecureRandom.random_number(p)
    bigB = g.to_bn.mod_exp(b, p)
    bob.secret_num = b
    bob.shared_key = bob.bigA.to_bn.mod_exp(b, p)
    network.send(bob, mitm, p, g, bigA, bigB)

    # mitm's side
    bigB = p
    network.send(mitm, alice, p, g, bigA, bigB)

    # alice's side
    alice.shared_key = alice.bigB.to_bn.mod_exp(a, p)
    ciphertext = alice.encrypt("hello")

    # now mitm should be able to decrypt ciphertext because the shared_key is
    # simply derived from 0 - p ^ a (mod p) is 0
    mitm.shared_key = 0
    puts mitm.decrypt(ciphertext)
end

def challenge35()
    # alice's side
    alice = Some.new
    p = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'
    p = p.to_i(16)
    g = 2
    alice.p = p
    alice.g = g

    mitm = Some.new
    bob = Some.new
    network = Network.new
    network.send(alice, mitm, p, g, nil, nil)
    #new_g = 1
    #new_g = p
    new_g = p-1 
    g = new_g
    mitm.g = new_g
    network.send(mitm, bob, p, g, nil, nil)
    network.send(mitm, alice, p, g, nil, nil) # consider this as ack message (new g is sent)
    a = SecureRandom.random_number(p)
    bigA = g.to_bn.mod_exp(a, p)
    alice.secret_num = a
    alice.bigA = bigA
    network.send(alice, mitm, p, g, bigA, nil)

    # mitm's side
    network.send(mitm, bob, p, g, bigA, nil)

    # bob's side
    b = SecureRandom.random_number(p)
    bigB = g.to_bn.mod_exp(b, p)
    bob.secret_num = b
    bob.shared_key = bob.bigA.to_bn.mod_exp(b, p)
    network.send(bob, mitm, p, g, bigA, bigB)

    # mitm's side
    network.send(mitm, alice, p, g, bigA, bigB)

    # alice's side
    alice.shared_key = alice.bigB.to_bn.mod_exp(a, p)
    ciphertext = alice.encrypt("hello")

    if g == 1
        mitm.shared_key = 1
    elsif g == p
        mitm.shared_key = 0
    elsif g == p-1
        mitm.shared_key = p-1
    end
    puts mitm.decrypt(ciphertext)
end

class SRPServer
    def initialize(n, g, k)
	@n = n
	@g = g
	@k = k
	@salts = Hash.new # per user
	@verifiers = Hash.new # per user
	@u = Hash.new # per user
	@keys = Hash.new # per user
    end

    def register(username, salt, verifier)
	# server should prevent having users with the same verifier
	@salts[username] = salt
	@verifiers[username] = verifier
    end

    def step1(username, bigA)
	salt = @salts[username]
        b = SecureRandom.random_number(@n)
	v = @verifiers[username]
        bigB = @k * v + @g.to_bn.mod_exp(b, @n)
        uH = Digest::SHA256.hexdigest(bigA.to_s(16)+bigB.to_s(16))
        u = uH.hex
	@u = u
    	s = (bigA.to_bn * v.mod_exp(u, @n)).mod_exp(b, @n) 
    	k = Digest::SHA256.hexdigest(s.to_s(16))
	@keys[username] = k
	return salt, bigB
    end

    def step2(username, hmac)
	salt = @salts[username]
        digest = OpenSSL::Digest.new('sha256')
	key = @keys[username]
        h = OpenSSL::HMAC.hexdigest(digest, key, salt.to_s)
   	puts h
	if h == hmac
	    return true
	else
	    return false
	end
    end
end

class SRPServerMalicious
    def initialize(n, g, k)
	@n = n
	@g = g
	@k = k
	@salts = Hash.new # per user
	@verifiers = Hash.new # per user
	@u = Hash.new # per user
	@keys = Hash.new # per user
	@bs = Hash.new
	@bigAs = Hash.new
	@passwords = []
	words = {}
	File.open("/usr/share/dict/words") do |text|
  	    text.each do |line|
    		@passwords.push(line.strip)
  	    end
	end
    end

    def register(username, salt, verifier)
	# server should prevent having users with the same verifier
	@salts[username] = salt
	@verifiers[username] = verifier
    end
    
    def step1(username, bigA)
	salt = @salts[username]
        b = SecureRandom.random_number(@n)
	v = @verifiers[username]
        #bigB = @k * v + @g.to_bn.mod_exp(b, @n)
        bigB = @g.to_bn.mod_exp(b, @n)
        #uH = Digest::SHA256.hexdigest(bigA.to_s(16)+bigB.to_s(16))
	uH = SecureRandom.hex
        u = uH.hex
	@u = u
	@bs[username] = b
	@bigAs[username] = bigA
	# you don't know the password:
    	#s = (bigA.to_bn * v.mod_exp(u, @n)).mod_exp(b, @n) 
    	#k = Digest::SHA256.hexdigest(s.to_s(16))
	#@keys[username] = k
	return salt, bigB, u
    end

    def step2(username, hmac)
	salt = @salts[username]
        digest = OpenSSL::Digest.new('sha256')
	b = @bs[username]
	bigA = @bigAs[username]

	for p in @passwords
	    xH = Digest::SHA256.hexdigest(salt + p.force_encoding('BINARY'))
    	    x = xH.hex
    	    v = @g.to_bn.mod_exp(x, @n)

    	    s = (bigA.to_bn * v.mod_exp(@u, @n)).mod_exp(b, @n) 
    	    k = Digest::SHA256.hexdigest(s.to_s(16))
	    
            h = OpenSSL::HMAC.hexdigest(digest, k, salt.to_s)
	    if h == hmac
		puts h
		return true
	    end
	end
	return false
    end
end

def challenge36()
    n = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'.to_i(16)
    g = 2
    k = 3
    i = "user"
    p = "password"
    salt = SecureRandom.random_bytes(16)
    xH = Digest::SHA256.hexdigest(salt + p)
    x = xH.hex
    v = g.to_bn.mod_exp(x, n)
    x = nil

    server = SRPServer.new(n, g, k)
    server.register(i, salt, v)

    a = SecureRandom.random_number(n)
    bigA = g.to_bn.mod_exp(a, n)
    salt, bigB = server.step1(i, bigA)

    uH = Digest::SHA256.hexdigest(bigA.to_s(16)+bigB.to_s(16))
    u = uH.hex
    xH = Digest::SHA256.hexdigest(salt + p)
    x = xH.hex
    s = (bigB - k * g.to_bn.mod_exp(x, n)).to_bn.mod_exp(a + u * x, n)
    k = Digest::SHA256.hexdigest(s.to_s(16))
    digest = OpenSSL::Digest.new('sha256')
    hmac = OpenSSL::HMAC.hexdigest(digest, k, salt.to_s)
    puts hmac
    ok = server.step2(i, hmac)
    puts ok
end

def challenge37()
    n = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'.to_i(16)
    g = 2
    k = 3
    i = "user"
    p = "password"
    salt = SecureRandom.random_bytes(16)
    xH = Digest::SHA256.hexdigest(salt + p)
    x = xH.hex
    v = g.to_bn.mod_exp(x, n)
    x = nil

    server = SRPServer.new(n, g, k)
    server.register(i, salt, v)

    #a = SecureRandom.random_number(n)
    #bigA = g.to_bn.mod_exp(a, n)
    bigA = n*2
    salt, bigB = server.step1(i, bigA)

    uH = Digest::SHA256.hexdigest(bigA.to_s(16)+bigB.to_s(16))
    u = uH.hex
    xH = Digest::SHA256.hexdigest(salt + p)
    x = xH.hex
    #s = (bigB - k * g.to_bn.mod_exp(x, n)).to_bn.mod_exp(a + u * x, n)
    s = 0
    k = Digest::SHA256.hexdigest(s.to_s(16))
    digest = OpenSSL::Digest.new('sha256')
    hmac = OpenSSL::HMAC.hexdigest(digest, k, salt.to_s)
    puts hmac
    ok = server.step2(i, hmac)
    puts ok
end

def challenge38()
    n = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'.to_i(16)
    g = 2
    k = 3
    i = "user"
    p = "Dante"
    salt = SecureRandom.random_bytes(16)
    xH = Digest::SHA256.hexdigest(salt + p)
    x = xH.hex
    v = g.to_bn.mod_exp(x, n)
    x = nil

    server = SRPServerMalicious.new(n, g, k)
    server.register(i, salt, v)

    a = SecureRandom.random_number(n)
    bigA = g.to_bn.mod_exp(a, n)
    salt, bigB, u = server.step1(i, bigA)

    #uH = Digest::SHA256.hexdigest(bigA.to_s(16)+bigB.to_s(16))
    #u = uH.hex
    xH = Digest::SHA256.hexdigest(salt + p)
    x = xH.hex
    #s = (bigB - k * g.to_bn.mod_exp(x, n)).to_bn.mod_exp(a + u * x, n)
    s = bigB.to_bn.mod_exp(a + u * x, n)
    k = Digest::SHA256.hexdigest(s.to_s(16))
    digest = OpenSSL::Digest.new('sha256')
    hmac = OpenSSL::HMAC.hexdigest(digest, k, salt.to_s)
    puts hmac
    ok = server.step2(i, hmac)
    puts ok
end

def gcd(x, y)
    # Euclidean algorithm
    # http://pages.pacificcoast.net/~cazelais/222/xeuclid.pdf
    if x > y
	a = x
	b = y
    else
	a = y
	b = x
    end
    if b == 0
	return a
    else
        c = a - b
	return gcd(b, c)
    end
end

#coeff = Util.xgcd(32, 12, [1,0], [0,1]) # should be 4, -1, 3
#coeff = Util.xgcd(76, 32, [1,0], [0,1]) # should be 4, 3, -7
#puts coeff

def challenge39()
    rsa = RSA.new
    c = rsa.encrypt('hello')
    puts rsa.decrypt(c)
end

def challenge40()
    rsa1 = RSA.new
    rsa2 = RSA.new
    rsa3 = RSA.new
    c1 = rsa1.encrypt('hello')
    c2 = rsa2.encrypt('hello')
    c3 = rsa3.encrypt('hello')
    n_1 = rsa1.n
    n_2 = rsa2.n
    n_3 = rsa3.n
    n = (n_1 * n_2 * n_3)

    gcd, x, y = Util.xgcd(n_1, n_2*n_3, [1,0], [0,1])
    e_1 = y * n_2 * n_3

    gcd, x, y = Util.xgcd(n_2, n_1*n_3, [1,0], [0,1])
    e_2 = y * n_1 * n_3

    gcd, x, y = Util.xgcd(n_3, n_1*n_2, [1,0], [0,1])
    e_3 = y * n_1 * n_2
    x = c1 * e_1 + c2 * e_2 + c3 * e_3
    puts c1
    puts c2
    puts c3
    puts "--"
    puts (c1 * e_1) % n_1
    puts (c2 * e_2) % n_1
    puts (c1 * e_1) % n_1 + (c2 * e_2) % n_1
    # x and m (m is number that corresponds to the message) are congruent modulo n_1*n_2*n_3 (by Chinese remainder theorem)
    n = n_1 * n_2 * n_3
    nx = x % n
    if nx < 0
   	# this is just a heck to make nx positive (sometimes ruby returns negative number
	# when calculating modulo of the negative number)
        nx = nx - nx * n 
        nx = nx % n
    end
    mc = Util.nthroot(3, nx.to_i)
    m = [mc.to_i.to_s(16)].pack('H*')
    puts m
end

#challenge33()
#challenge34()
#challenge35()
#challenge36()
#challenge37()
#challenge38()
#challenge39()
challenge40()





