require 'securerandom'
require_relative 'util'
require_relative 'sha1'
require_relative 'md4'
require 'digest/sha1'
require 'net/http'

$key = SecureRandom.random_bytes
$nonce = SecureRandom.random_bytes[0..7]

def edit(ciphertext, offset, newtext)
    plaintext = Util.ctr_encrypt(ciphertext, $key, $nonce)
    if offset == 0
        newplaintext = newtext
    else
        newplaintext = plaintext[0..offset-1] + newtext
    end
    #puts newplaintext
    if newplaintext.length < plaintext.length
        newplaintext += plaintext[offset+newtext.length..plaintext.length-1]
    end
    #puts newplaintext
    newciphertext = Util.ctr_encrypt(newplaintext, $key, $nonce)
    newciphertext
end

def challenge25()
    f = open('chall25.txt')
    text = f.read
    ciphertext = Util.ctr_encrypt(text, $key, $nonce)
    puts edit(ciphertext, 0, ciphertext)
end

def f1(t)
    t = t.gsub(/[=;]/, '!')
    t = "comment1=cooking%20MCs;userdata=" + t
    t = t + ";comment2=%20like%20a%20pound%20of%20bacon"
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    nonce = "0" * 8
    c = Util.ctr_encrypt(t, key, nonce)
    c
end

def f2(c)
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    nonce = "0" * 8
    d = Util.ctr_encrypt(c, key, nonce)
    if d.match(/;admin=true/)
        return true
    else
        return false
    end
end

def challenge26()
    t = "x" * 5 + ";admin=true"
    c = f1(t)

    f = Util.xor("!", ";")
    c[37] = Util.xor(f, c[37])

    f = Util.xor("!", "=")
    c[43] = Util.xor(f, c[43])
    puts f2(c)
end

def f1_challenge16(t)
    key = "A" * 16
    iv = key # make the key and iv the same for challenge 27
    c = Util.cbc_encrypt(t, iv, key)
    c
end

def f2_challenge16(c)
    key = "A" * 16
    iv = key # make the key and iv the same for challenge 27
    d = Util.cbc_decrypt(c, iv, key)
    for i in (0..d.length-1)
	if d[i].ord > 127
	    raise d
	end
    end
end

def challenge27()
    t = "B" * 22 + 129.chr + 130.chr + "C" * 20
    c = f1_challenge16(t)
    modified_c = c[0..15] + 0.chr * 16 + c[0..15]
    begin
        puts f2_challenge16(modified_c)
    rescue Exception => e
	puts "Exception occured! The decrypted value is:"
        puts e
	p = e.to_s
        key = Util.xor(p[0..15], p[32..47])
	puts "The key is: " + key
    end
end

def challenge28()
    key = "some_key"
    m = "test"
    a = authSHA1(key, m)
    puts a
end

def hash_oracle(message)
    key = "some_key"
    a = authSHA1(key, message)
end

def challenge29()
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    key_length = 8
    a = hash_oracle(message)
    # key + message needs to be padded
    fill   = "\x00"*(64 - (key_length + message.length+9)%64)
    length = "\x00" * 4 + [(key_length + message.length)*8].pack("N*")
    #padded_message_without_key = message + "\x80" + fill + length
    padded_message_without_key = message + "\x80" + fill # although the padding is calculated as the key would be prepended
    p = padded_message_without_key.unpack("N*")
    p.push(0)
    p.push((key_length + message.length)*8)
    padded_message_without_key = p.pack("N*")

    appendix = ";admin=true"
    fill   = "\x00"*(64 - (appendix.length+9)%64)
    l = appendix.length * 8 + padded_message_without_key.length * 8 + key_length * 8
    #padded_appendix = appendix + "\x80" + fill + length # this throws some exception (utf8, ascii)
    padded_appendix = appendix + "\x80" + fill
    padded_appendix = padded_appendix.unpack("N*")
    padded_appendix.push(0)
    padded_appendix.push(l)
    #puts "+++++"
    #puts padded_appendix.join(",")

    chain = Array.new
    for i in (0..(a.length/8)-1)
        chain[i] = a[i*8..(i+1)*8-1]	
    end
    chain = chain.map{|c| c.hex}
    a1 = SHA1.compress(padded_appendix, chain)

    a11 = a1.map{|c| "%08x"%c}.join("")
    puts "calculated hash without knowing the key:"
    puts a11

    test = hash_oracle(padded_message_without_key + appendix)
    # test and a11 should be the same
    puts "hash of the constructed message (knowing the key):"
    puts test
end

def md4_padding(message, size)
    mask = (1 << 32) - 1
    message_size = message.size
    if size
        message_size = size
    end
    bit_len = message_size << 3
    message += "\x80"
    while (message_size % 64) != 56
        message += "\0"
        message_size = message.size
    end
    message = message.force_encoding('ascii-8bit') + [bit_len & mask, bit_len >> 32].pack("V2")
    message
end

def md4_hash_oracle(message)
    key = "some_key"
    a = authMD4(key, message)
end

def challenge30()
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    key_length = 8
    s = md4_hash_oracle(message)
    padded_message_with_fake_key = md4_padding("a" * key_length + message, nil)
    #padded_message_with_key = md4_padding("some_key" + message, nil) # although the padding is calculated as the key would be prepended
    #puts padded_message_with_key.bytes.join(",")
    #puts padded_message_with_key.length

    appendix = ";admin=true"
    padded_appendix = md4_padding(appendix, 
      padded_message_with_fake_key.length + appendix.length)
    
    a, b, c, d = s.pack("H*").unpack("V4")

    x = padded_appendix.unpack("V16")

    block = padded_appendix
    #puts block
    #puts block.bytes.join(",")
    x = block.unpack("V16")
    #puts x.join(",")
    #puts "--------------------------"

    mask = (1 << 32) - 1
    f = proc {|x, y, z| x & y | x.^(mask) & z}
    g = proc {|x, y, z| x & y | x & z | y & z}
    h = proc {|x, y, z| x ^ y ^ z}
    r = proc {|v, s| (v << s).&(mask) | (v.&(mask) >> (32 - s))}
 
    aa, bb, cc, dd = a, b, c, d
    [0, 4, 8, 12].each {|i|
      a = r[a + f[b, c, d] + x[i],  3]; i += 1
      d = r[d + f[a, b, c] + x[i],  7]; i += 1
      c = r[c + f[d, a, b] + x[i], 11]; i += 1
      b = r[b + f[c, d, a] + x[i], 19]
    }
    [0, 1, 2, 3].each {|i|
      a = r[a + g[b, c, d] + x[i] + 0x5a827999,  3]; i += 4
      d = r[d + g[a, b, c] + x[i] + 0x5a827999,  5]; i += 4
      c = r[c + g[d, a, b] + x[i] + 0x5a827999,  9]; i += 4
      b = r[b + g[c, d, a] + x[i] + 0x5a827999, 13]
    }
    [0, 2, 1, 3].each {|i|
      a = r[a + h[b, c, d] + x[i] + 0x6ed9eba1,  3]; i += 8
      d = r[d + h[a, b, c] + x[i] + 0x6ed9eba1,  9]; i -= 4
      c = r[c + h[d, a, b] + x[i] + 0x6ed9eba1, 11]; i += 8
      b = r[b + h[c, d, a] + x[i] + 0x6ed9eba1, 15]
    }
    a = (a + aa) & mask
    b = (b + bb) & mask
    c = (c + cc) & mask
    d = (d + dd) & mask

    a11 = [a, b, c, d].pack("V4").unpack("H*")
    puts a11

    s1 = md4_hash_oracle(padded_message_with_fake_key[key_length..padded_message_with_fake_key.length-1] + appendix)
    puts s1
end

def challenge31()
    # start server31.rb first
    file = "foo"
    signature = Util.hmac("key", file) 
    puts signature
    # try to guess a signature:
    signature = ""
    s = ""
    for j in (0..19)
        times = Hash.new
	winner = ""
	diff = 0
        for i in (0..255)
	    h = i.chr.unpack("H*")[0]
	    start = Time.now
    	        url = "http://localhost:4567/test?file=#{file}&signature=#{s+h}"
    	        resp = Net::HTTP.get_response(URI.parse(url))
	    finish = Time.now
	    #diff = finish - start
	    if finish - start > diff
	        diff = finish - start
	 	winner = h
	    end
	    #times[h] = diff
        end
        #a = times.max_by{|k, v| v}
        #signature += a[0]
        #s += a[0]
        s += winner
	puts s
    end
    puts signature
  
    resp_text = resp.body
    puts resp_text
end

def challenge32()
    # start server32.rb first
    file = "foo"
    signature = Util.hmac("key", file) 
    puts signature
    puts "this takes some time ... "
    # try to guess a signature:
    signature = ""
    s = ""
    for j in (0..19)
        times = Hash.new
        for i in (0..255)
	    h = i.chr.unpack("H*")[0]
	    sum = 0
	    for k in (0..9)
	        start = Time.now
    	            url = "http://localhost:4567/test?file=#{file}&signature=#{s+h}"
    	            resp = Net::HTTP.get_response(URI.parse(url))
	        finish = Time.now
	        diff = finish - start
	 	sum += diff
	    end
	    times[h] = sum
        end
	#puts times
        a = times.max_by{|k, v| v}
        signature += a[0]
        s += a[0]
	puts s
    end
    puts signature
  
    resp_text = resp.body
    puts resp_text
end


#challenge25()
#challenge26()
#challenge27()
#challenge28()
#challenge29()
#challenge30()
#challenge31()
#challenge32()

