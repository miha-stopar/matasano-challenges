require 'openssl'
require 'set'

module Util
    @ctr_counter = 0
   
    def Util.ctr_encrypt(text, key, nonce)
        cipher = OpenSSL::Cipher.new("AES-128-ECB")
        cipher.padding = 0 # otherwise bad decrypt is thrown (padding is added by OpenSSL)
        cipher.encrypt
        cipher.key = key

	c = ""
	blocks = text.length / 16
	if text.length % 16 == 0
	    blocks -= 1	
	end
        for i in (0..blocks)
	    tblock = text[i*16..(i+1)*16-1]
	    counter = [i].pack("Q")
	    #counter = [@ctr_counter].pack("Q")
            enc = cipher.update(nonce+counter) + cipher.final
	    if enc.length > tblock.length
	        enc = enc[0..tblock.length-1]
	    end
	    c += Util.xor(enc, tblock)
	    #@ctr_counter += 1
	end
	c
    end

    def Util.check_and_remove_pkcs7_padding(text)
        padds = Set.new
	lc = text[-1,1] # this way the last byte is not transoformed into ord (as if text[-1])
	if text[text.length-lc.ord..text.length-1] == lc * lc.ord and lc.ord != 0
            return text[0..text.length-lc.ord-1]
        else
            raise "not valid padding"
        end
    end

    def Util.pkcs7_padding(text, block_size)
        text_length = text.length
        m = text_length % block_size
        c = block_size - m
        if m == 0
            c = block_size
        end
        new_block = text + c.chr * c
        new_block
    end

    def Util.cbc_encrypt(text, iv, key)
        cipher = OpenSSL::Cipher.new("AES-128-ECB")
        cipher.padding = 0 # otherwise bad decrypt is thrown (padding is added by OpenSSL)
        cipher.encrypt
        cipher.key = key
        block_size = iv.length
        padded_text = pkcs7_padding(text, block_size)
        chain_length = padded_text.length / block_size
        c_text = iv
        for i in (0..chain_length-1)
            f = c_text[-block_size..-1]
            s = padded_text[i*block_size..i*block_size+block_size-1]
            xored = Util.xor(f, s)
            xored_enc = cipher.update(xored) + cipher.final
            c_text += xored_enc
        end
        c_text = c_text[block_size..-1]
        c_text
    end

    def Util.cbc_decrypt(text, iv, key)
        cipher = OpenSSL::Cipher.new("AES-128-ECB")
        cipher.decrypt
        cipher.padding = 0 # otherwise bad decrypt is thrown (padding is added by OpenSSL)
        cipher.key = key
        block_size = iv.length
        first_block = cipher.update(text[0..block_size-1]) + cipher.final
        plain_first = Util.xor(first_block, iv)
        chain_length = text.length / block_size
        d_text = plain_first
        for i in (1..chain_length-1)
            f = text[block_size*i..block_size*(i+1)-1]
            d = cipher.update(f) + cipher.final
	    p = Util.xor(d, text[block_size*(i-1)..block_size*i-1])
            d_text += p
        end
        d_text
    end

    def Util.hmac(key, message)
        block_size = 64
        if key.length > block_size
          key = [Digest::SHA1.hexdigest(key)].pack("H*")
        end
        if key.length < block_size
          l = (block_size - key.length)
          padding = 0.chr * l
          key = key + padding
        end
        opad = ["5c"].pack("H*") * block_size
        ipad = ["36"].pack("H*") * block_size
        t1 = Util.xor(key, opad)
        c1 = Util.xor(key, ipad) + message
        t2 = Digest::SHA1.hexdigest(c1)
        hmac = Digest::SHA1.hexdigest(t1 + [t2].pack("H*"))
        hmac
    end

    def Util.base64_to_hex(s)
        b = s.unpack("m0")
        c = b[0].unpack("H*")
        c[0]
    end

    def Util.hex_to_base64(hex)
        [[hex].pack("H*")].pack("m0")
    end

    def Util.hex_to_binary(hex)
        b = [hex].pack("H*").unpack("B*")
        b[0]
    end

    def Util.xor(s1, s2)
	h1 = s1.unpack("H*")[0]
	h2 = s2.unpack("H*")[0]
	h = xor_two_hexes(h1, h2)
    	[h].pack("H*") 
    end

    def Util.xor_two_binaries(b1, b2)
        a1 = b1.split("").map {|a| a.to_i}
        a2 = b2.split("").map {|a| a.to_i}
        a3 = a1.zip(a2) 
        c = a3.map {|a,b| a^b}
        g = c.join()
        e = [g].pack("B*")
        e.unpack("H*")[0] # returns hex
    end
    
    def Util.xor_two_hexes(hex1, hex2)
        b1 = hex_to_binary(hex1)
        b2 = hex_to_binary(hex2)
        r = xor_two_binaries(b1, b2)
        r
    end 

    def Util.get_repeated_blocks_and_indices(text, block_size)
        j = 0
	bs = Hash.new
        while j+block_size-1 < text.length
	    f = text[j..j+block_size-1]
	    if bs[f] == nil
	        bs[f] = []
	    end
	    bs[f].push(j)
            j += 1
        end
	selected = bs.select {|x,y| y.length > 1}
	return selected
    end

    def Util.get_repeated_blocks_hex(hex_text, block_size)
	bs = Hash.new(0)
        j = 0
        while j+block_size-1 < hex_text.length
            #bs[hex_text[j..j+block_size-1]] += 1
	    f = hex_text[j..j+block_size-1].unpack("H*")
            bs[f] += 1
            j += 2 # because it is hex
        end
	return bs
    end

    def Util.count_repeated_blocks(hex_text, block_size)
	# counts the repetitions - not necessarily of the same text
	bs = get_repeated_blocks_hex(hex_text, block_size)
	selected = bs.select {|x,y| y > 1}
	if selected.length > 0
	    counts = selected.map {|x,y| y}
	    repeated_instances = counts.length
	    s = counts.reduce(:+)
	    return s - repeated_instances
	else
	    return 0
	end
    end

    def Util.xor_with_all_chars_and_find_winner(h1)
        most_probable_key = ""
        highest_perc = 0
        for i in 0..255
            r = xor_with_single_byte(h1, i)
            s = [r].pack("H*")
            perc = meaningful_chars_percentage(s)
            if perc > 0.85  and perc > highest_perc
                most_probable_key = i
                highest_perc = perc
            end
        end
	if most_probable_key == ""
	    return nil
	else
            return most_probable_key
	end
    end

    def Util.xor_with_single_byte(hex, ascii_key)
        h = ascii_key.to_s(16)

        if h.length < 2
            h = "0" + h
        end
        nh = h * (hex.length / 2)
        r = Util.xor_two_hexes(hex, nh)
        r
    end

    def Util.meaningful_chars_percentage(s)
        s1 = s.split("")
        #f = s1.select {|x| x[0] == 32 or x[0] == 39 or x[0] == 44 or x[0] == 46 or (x[0] > 64 and x[0] < 91) or (x[0] > 96 and x[0] < 123)}
        #f = s1.select {|x| ?x.ord == 32 or ?x.ord == 39 or ?x.ord == 44 or ?x.ord == 46 or (?x.ord > 64 and ?x.ord < 91) or (?x.ord > 96 and ?x.ord < 123)}
        #f = s1.select {|x| ?x == 32 or ?x == 39 or ?x == 44 or ?x == 46 or (?x > 64 and ?x < 91) or (?x > 96 and ?x < 123)}
        f = s1.select {|x| x.ord == 32 or x.ord == 39 or x.ord == 44 or x.ord == 46 or (x.ord > 64 and x.ord < 91) or (x.ord > 96 and x.ord < 123)}
        tscore = f.length
        perc = tscore / s.length.to_f
        if perc == 1.0
            #puts s
            #puts "---"
            #puts f.join()
            #puts perc
            #puts "----------------------"
        end
        perc
    end

    def Util.invmod(et, e)
	# find inverse of e in Z_et\*
        gcd, x, y = xgcd(et, e, [1,0], [0,1])
        # x * et + y * e = gcd
        raise 'gcd(et, e) is not 1' unless gcd == 1
        return y % et
    end

    def Util.xgcd(some_a, some_b, coeff_a, coeff_b)
        # Extended Euclid
        # if some_b > some_a the next iteration will get these two parameters exchanged
        some_a_x = coeff_a[0]
        some_a_y = coeff_a[1]
        some_b_x = coeff_b[0]
        some_b_y = coeff_b[1]
        #puts "#{a}, #{b}, [#{some_a_x}, #{some_a_y}], [#{some_b_x}, #{some_b_y}]"
        # some_a = some_a_x * a + some_a_y * b
        # some_b = some_b_x * a + some_b_y * b
        if some_b == 0
            return [some_a, some_a_x, some_a_y]
        end
        k1 = some_a / some_b
        if k1.class == Array # when OpenSSL:BN is divided by some number, it returns an Array with result and remainder
            k1 = k1[0]
        end
        r1 = some_a % some_b
        # express remainder as a pair of coefficients of the current some_a and some_b
        #r1 = some_a - some_b * k1 
        #r1 = some_a_x * a + some_a_y * b - (some_b_x * a + some_b_y * b) * k1
        #r1 = (some_a_x - some_b_x * k1) * a + (some_a_y - some_b_y * k1) * b
        coeff = xgcd(some_b, r1, [some_b_x, some_b_y], [some_a_x-some_b_x*k1, some_a_y-some_b_y*k1])
        return coeff
    end

    def Util.nthroot(n, a, precision = 1e-320)
        #a = a.to_i
        #x = Float(a)
	x = a
        next_x = 0
        while true do
            next_x = ((n - 1) * x + a / (x ** (n - 1))) / n
            if (next_x - x).abs < precision
                return next_x
            end
            x = next_x
        end
    end

end
