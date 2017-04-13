require 'openssl'
require_relative 'util'
#require 'util'
require 'securerandom'
require 'set'

def challenge9()
    puts "Challenge 9..."
    p = Util.pkcs7_padding("asdf", 6)
    raise "not properly padded" unless p[4].ord == 2 and p[5].ord == 2
end

def challenge10_test()
    iv = "0123456789123456"
    text = "this is a test. this is a test. this is a test."
    key = SecureRandom.random_bytes
    c = Util.cbc_encrypt(text, iv, key)
    s = Util.cbc_decrypt(c, iv, key)
    puts s
end

def challenge10()
    puts "Challenge 10..."
    key = "YELLOW SUBMARINE"
    c = File.read("set2chall10.txt")
    c = c.unpack("m").join()
    iv = ["00" * 16].pack("H*")
    s = Util.cbc_decrypt(c, iv, key)
    b = s[0..7]
    puts "decrypted message starts with:"
    puts b
    raise "message not decrypted properly" unless b == "I'm back"
end

def encryption_sth(text)
    key = SecureRandom.random_bytes
    key = "0123456789123456"
    append_before_count = rand(5) + 6
    append_after_count = rand(5) + 6
    #text = "0" * append_before_count + text
    #text = text + "0" * append_after_count
    use_cbc = rand(2)
    if use_cbc == 1
        puts "cbc"
        iv = SecureRandom.random_bytes
    	c = Util.cbc_encrypt(text, iv, key)
    else # ecb
        puts "ecb"
	cipher= OpenSSL::Cipher.new("AES-128-ECB")
    	cipher.encrypt
    	cipher.key = key
    	c = cipher.update(text) + cipher.final
    end
    c
end

def challenge11()
    text = "test" * 4 * 4
    c = encryption_sth(text)
    count = Util.count_repeated_blocks(c, 16)
    if count > 0
	puts "repeated blocks detected - AES ECB encoded"
    end
end

def oracle12(text)
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    cipher = OpenSSL::Cipher.new("AES-128-ECB")
    cipher.encrypt
    cipher.key = key
    b = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    h = Util.base64_to_hex(b)
    t = [h].pack("H*")
    nt = text + t
    c = cipher.update(nt) + cipher.final
    c
end

def get_block_size()
    s = Set.new
    for i in (1..100)
        nt = "A" * i
	t = oracle12(nt)
	s.add(t.length)
    end
    a = s.to_a
    return a[1] - a[0]
end

def challenge12()
    block_size = get_block_size()
    t = oracle12("A" * 2 * block_size)
    count = Util.count_repeated_blocks(t, block_size)
    puts count
    if count > 0
	puts "ECB detected"
    else
	puts "not ECB"
	return
    end

    text_len = 138 # could be retrieved by calling oracle12 with empty argument (a few times to see what padding is required)
    num_blocks = text_len / block_size
    if text_len % block_size != 0
	num_blocks += 1
    end
  
    text_blocks = Hash.new
    text_blocks[0] = "A" * block_size
    for j in (1..num_blocks)
        w = ""
        for i in (1..block_size)
	    f = text_blocks[j-1][i..block_size-1] + w
	    dict = gen_dict(f)
            c = oracle12("A" * (block_size-i))[(j-1)*block_size..j*block_size-1]
            s = dict[c]
	    if (j-1) * block_size + i == text_len
		break
	    end 
	    w += s[-1]
        end
	text_blocks[j] = w
    end
    puts text_blocks.values.reduce(:+)[block_size..-1]
end

def gen_dict(t)
    # gets string (length 15), concatenate it with every possible byte and "oracle"
    # concatenated string
    dict = Hash.new
    for i in (0..255)
    	s = t.dup
        s += i.chr
	dict[oracle12(s)[0..15]] = s
    end
    dict
end

def parse(c)
    els = c.split("&")
    h = Hash.new
    for el in els
	k = el.split("=")[0]
	v = el.split("=")[1]
	h[k] = v
    end 
    return h
end

def profile_for(t)
    if t.include? "=" or t.include? "&"
	return
    end
    h = Hash.new
    h["email"] = t
    h["uid"] = 10
    h["role"] = "user"
    t = "email=#{t}&uid=10&role=user"
    return t
end

def enc_profile(key, user_profile)
    cipher = OpenSSL::Cipher.new("AES-128-ECB")
    cipher.encrypt
    cipher.key = key
    enc = cipher.update(user_profile) + cipher.final
    return enc
end

def dec_profile(key, enc)
    cipher = OpenSSL::Cipher.new("AES-128-ECB")
    cipher.decrypt
    cipher.key = key
    dec = cipher.update(enc) + cipher.final
    return dec
end

def challenge13()
    parse("foo=bar&baz=qux&zap=zazzle")
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    p = profile_for("a" * 10 + "admin" + "\x0b" * 11) # make it that "admin" with appropriate padding will be the second block ("aa..." follows "email=")
    enc = enc_profile(key, p)
    admin = enc[16..31] # this is in what "admin" + "\x0b" * 11 is encrypted

    email = "foo@bar.com"
    user_profile = profile_for("xx" + email) # add two letters to push "user" into third block
    enc = enc_profile(key, user_profile)
    bla = enc[0..31] + admin

    dec = dec_profile(key, bla)
    puts dec
    parsed = parse(dec)
    puts parsed
end

def oracle14(text)
    t = "0" * 7
    text = t + text
    o = oracle12(text)
end

def challenge14()
    # this is pretty much the same as challenge12, except when calling oracle14 instead of 
    # oracle12 (there is a slight difference in the argument as well - there are prepended
    # characters and the block that is of interest is the next one (comparing to the
    # oracle12
    t = "A"
    while true do
        c = oracle14(t)
        count = Util.count_repeated_blocks(c, 16)
 	if count > 0
	    break
	end
	t += "A"
    end
    prepend_length = t.length - 2 * 16

    block_size = get_block_size()
    text_len = 138 # could be retrieved by calling oracle12 with empty argument (a few times to see what padding is required)
    num_blocks = text_len / block_size
    if text_len % block_size != 0
	num_blocks += 1
    end
  
    text_blocks = Hash.new
    text_blocks[0] = "A" * block_size
    for j in (1..num_blocks)
        w = ""
        for i in (1..block_size)
	    f = text_blocks[j-1][i..block_size-1] + w
	    dict = gen_dict(f)
            c = oracle14("0" * prepend_length + "A" * (block_size-i))[(j)*block_size..(j+1)*block_size-1]
            s = dict[c]
	    if (j-1) * block_size + i == text_len
		break
	    end 
	    w += s[-1]
        end
	text_blocks[j] = w
    end
    puts text_blocks.values.reduce(:+)[block_size..-1]
end

def challenge15()
    s1 = "ICE ICE BABY\x04\x04\x04\x04"
    begin
        s = Util.check_and_remove_pkcs7_padding(s1)
        puts s
    rescue
        puts "not properly padded:"
        puts s1
    end
    s1 = "ICE ICE BABY\x05\x05\x05\x05"
    begin
        s = Util.check_and_remove_pkcs7_padding(s1)
        puts s
    rescue
        puts "not properly padded:"
        puts s1
    end
    s1 = "ICE ICE BABY\x01\x02\x03\x04"
    begin
        s = Util.check_and_remove_pkcs7_padding(s1)
        puts s
    rescue
        puts "not properly padded:"
        puts s1
    end
end

def f1(t)
    t = t.gsub(/[=;]/, '!')
    t = "comment1=cooking%20MCs;userdata=" + t
    t = t + ";comment2=%20like%20a%20pound%20of%20bacon"
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    iv = "0" * 16
    c = Util.cbc_encrypt(t, iv, key)
    c
end

def f2(c)
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    iv = "0" * 16
    d = Util.cbc_decrypt(c, iv, key)
    if d.match(/;admin=true/) 
	return true
    else
        return false
    end
end

def challenge16()
    t = "x" * 5 + ";admin=true"
    c = f1(t)

    f = Util.xor("!", ";")
    c[21] = Util.xor(f, c[21])

    f = Util.xor("!", "=")
    c[27] = Util.xor(f, c[27])
    puts f2(c)
end

challenge9()
#challenge10_test()
#challenge10()
#challenge11()
#challenge12()
#challenge13()
#challenge14()
#challenge15()
#challenge16()
