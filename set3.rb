require_relative 'util'
require_relative 'mersenne_twister'
#require 'util'

def f1(key)
    a = [
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
    text = a[rand(10)]
    puts text
    iv = "0123456789123456"
    c = Util.cbc_encrypt(text, iv, key)
    return c, iv
end

def f2(key, iv, c)
    d = Util.cbc_decrypt(c, iv, key)
    begin
        s = Util.check_and_remove_pkcs7_padding(d)
	return true
    rescue
	#puts "not properly padded"
	return false
    end
end

def challenge17()
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    c, iv = f1(key)
    
    ivc = iv + c
    plain = ""
    modified_ivc = ivc.dup

    inside_block_ind = 15
    block_ind = (c.length-1)/16 # block which is being modified (0-indexed, iv is the 0-th block)
    intermediate = " " * 16
    while block_ind > -1
      for j in (0..255)
        modified_ivc[block_ind*16 + inside_block_ind] = j.chr
	if inside_block_ind > 0
	  modified_ivc[block_ind*16..block_ind*16+inside_block_ind-1] = "\x00" * inside_block_ind
	end
	padding = (16 - inside_block_ind).chr
 	ind = 15
	
	while ind > inside_block_ind
          modified_ivc[block_ind*16 + ind] = Util.xor(padding, intermediate[ind])
	  ind -= 1
	end


        #if f2(key, iv, modified_ivc[16..-1])
        if f2(key, iv, modified_ivc)
	  i = Util.xor(j.chr, padding)
	  intermediate[inside_block_ind] = i
	  f = Util.xor(i, ivc[block_ind*16 + inside_block_ind])
  	  plain = f + plain
	  #puts plain

	  inside_block_ind -= 1	  
	  if inside_block_ind == -1
	    inside_block_ind = 15 
	    block_ind -= 1
  	    intermediate = " " * 16
	    current_length = modified_ivc.length
	    modified_ivc = ivc.dup
	    modified_ivc = modified_ivc[0..current_length-16-1]
	  end
          break
        end
      end
    end
    puts plain

end

def challenge18()
    s = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    key = "YELLOW SUBMARINE"
    text = s.unpack("m").join
    nonce = "\x00" * 8
    puts Util.ctr_encrypt(text, key, nonce)
end

def try_guess(guess, block)
    len = guess.length
    reps = Util.get_repeated_blocks_and_indices(block, len)
    filtered = Hash.new
    reps.each do |text, indices|
        filtered[text] = []
        for ind in indices
            bar = ind / 16
            foo = (ind+len-1) / 16
            if foo == bar # prevent occurences which span over two ciphertexts
	        # translate ind into the [relative position in the ciphertext, ciphertext number]
	        filtered[text].push({"rel" => ind % 16, "ciphertext"=>bar})
    	    end
        end
    end
    filtered.each do |rep_text, list_of_occurences|
	puts "====================================="
	puts rep_text
	puts list_of_occurences
	key_candidate = get_partial_key_based_on_guess(guess, rep_text, list_of_occurences, len)
	if key_candidate == nil
	    next
	end
	for i in (0..15)
	    if key_candidate[i] == ""
		key_candidate[i] = "\x00"
	    end
	end
	puts key_candidate
	key_g = key_candidate.values.join
	j = 0
	num = block.length / 16
	if block.length % 16 == 0
	    num -= 1
	end
	for j in (0..num)
	    puts Util.xor(block[j*16..(j+1)*16-1], key_g)
	    # if part of each text is legible, it means part of the key is correct
	end
    end
end

def get_partial_key_based_on_guess(guess, rep_text, list_of_occurences, len)
	key_candidate = Hash.new
        for i in (0..15)
       	    key_candidate[i] = ""
        end
        for j in (0..list_of_occurences.length-1)
	    occ_rel_position = list_of_occurences[j]["rel"]
            foo = Util.xor(rep_text, guess)
	    for k in (0..len-1)
		if key_candidate[occ_rel_position+k] != "" and key_candidate[occ_rel_position+k] != foo[k]
		    return nil
 		else
            	    key_candidate[occ_rel_position+k] = foo[k]
		end
	    end
	end
        return key_candidate
end

def challenge19()
    cipher_texts = Array.new
    nonce = "\x00" * 8
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    max_length = 0
    f = File.open("chall19.txt", "r")
    test = Hash.new
    jind = 0
    f.each_line do |line|
        b = line.chop
	text = b.unpack("m").join
	test[jind] = text
	jind += 1
        c = Util.ctr_encrypt(text, key, nonce)
	cipher_texts.push(c)
	if c.length > max_length
	    max_length = c.length
   	end
    end
    f.close

    #cipher_texts = Array.new
    #cipher_texts.push("the flowers are blue")
    #cipher_texts.push("the bear is an animal, isn't it. the tree is an elephant")
    blocks = Hash.new("") # merge texts encrypted with the same key in one long text
    cind = 0
    num_blocks = (max_length / 16) + 1
    if num_blocks % 16 == 0
	num_blocks -= 1
    end
    for b in (0..num_blocks-1)
        for c in cipher_texts
	    if b * 16 < c.length
	        blocks[b] += c[b*16..(b+1)*16-1]
	        cind += 1
	    end
	end
    end
    for b in (0..num_blocks-1)
	# this is not fully automated - try_guess needs to be called with different values and it 
 	# has to be checked whether for some guess word there is a legible output (part of each 
	# of the text)
	try_guess("I have ", blocks[b]) # "I have " gives gives the first 7 key bytes
	# ideally try_guess should check the legibility and return the key (part of it), but this 
	# is then pretty similar to what is done in challeng20 (checking whether text contains legible
	# characters) and I am not going into this
	# thus, pasted from try_guess with "I have ":
	key = {0=>"\xFE", 1=>"2", 2=>"k", 3=>"\xDA", 4=>"K", 5=>"7", 6=>"\x1A", 7=>"\x00", 8=>"\x00", 9=>"\x00", 10=>"\x00", 11=>"\x00", 12=>"\x00", 13=>"\x00", 14=>"\x00", 15=>"\x00"}
	# try_guess should be now checked with other words until all key bytes are found
	# or even easier - check the plain text that was found by "I have ", predict the ending
	# of some words that are cut in the middle, xor with cipher to get further key bytes and 
	# repeat the procedure
    end
end

def challenge20()
    cipher_texts = Array.new
    nonce = "\x00" * 8
    key = "\005q?\024\021\370\364\331\361S\023\036\334\030fq"
    max_length = 0
    f = File.open("chall20.txt", "r")
    test = Hash.new
    jind = 0
    f.each_line do |line|
        b = line.chop
	text = b.unpack("m").join
	test[jind] = text
	jind += 1
        c = Util.ctr_encrypt(text, key, nonce)
	cipher_texts.push(c)
	if c.length > max_length
	    max_length = c.length
   	end
    end
    f.close
    blocks = Hash.new # characters in the same block have been encrypted (xored) with the same character
    for i in (0..max_length-1)
	blocks[i] = ""
    	for ctext in cipher_texts
	    if ctext[i] != nil
	        blocks[i] += ctext[i]
	    end
	end
    end
    key = ""
    for j in (0..blocks.length-1)
	hex = blocks[j].unpack("H*")[0]
	winner = Util.xor_with_all_chars_and_find_winner(hex)
	if winner == nil
	    winner = 32 # the key for this byte will be wrong as it couldn't be calculated
	end
	key += winner.chr
    end
    ind = 0
    for ctext in cipher_texts
	k = key[0..ctext.length-1]
	puts ctext.length
	puts key.length
	puts k.length
	text = Util.xor(ctext, k)
	puts ind
	puts text
	puts test[ind]
	# some key bytes might be wrong, but the text is easily legible
	ind += 1
    end
end

def challenge21()
    mersenne = MersenneTwister.new(4)
    for i in (0..7)
        puts mersenne.extract_number
    end
end

def challenge22()
    sleep(rand(10))
    seed = Time.now.to_i
    puts seed
    mersenne = MersenneTwister.new(seed) 
    sleep(rand(10))
    r = mersenne.extract_number
    t = Time.now.to_i
    for seed_guess in (t-30..t) # the number needs to be high enough to reach the time when the program was started
        mersenne = MersenneTwister.new(seed_guess) 
	if r == mersenne.extract_number
	    puts seed_guess
	end
    end
end

def untemper4(y)
    # find u out of u ^ (u >> 4)
    u = (y >> 18) ^ y
    u
end

def untemper1(y)
    # find u out of u ^ (u >> 11)
    first11 = y >> 21
    second11 = ((y >> 10) & (2**11-1)) ^ first11
    last10 = (second11 >> 1) ^ (y & (2**10-1))
    return last10 + (second11<<10) + (first11<<21)
end

def untemper3(y)
    # find u out of u ^ ((u << 15) & mask)
    mask = 4022730752
    f = (y << 15) & mask # this is the same as (u << 15) & mask
    u = y ^ f
    u
end

def untemper2(y, l)
    # find u out of u ^ ((u << 7) & mask)
    mask = 2636928640
    last_seven_known = y & (2**7-1) # the last 7 of u
    # now in each iteration find 7 bits of u
    unknown_bits_counter = (y.to_s(2)).length - 7
    u = last_seven_known
    i = 1
    while unknown_bits_counter > -32 # unknown_bits_counter is a misleading name - the
	# length of u might be larger than of y
        known_bits_counter = (y.to_s(2)).length - unknown_bits_counter
        mask_seven = (mask >> known_bits_counter) & (2**7-1)
        anded = last_seven_known & mask_seven
        output_seven = (y >> known_bits_counter) & (2**7-1)
        found_seven = anded ^ output_seven
 	u += (found_seven << 7*i)
	i += 1
        last_seven_known = found_seven
        unknown_bits_counter -= 7
    end
    return u
end

def challenge23()
    mersenne = MersenneTwister.new(Time.now.to_i)
    mt = Array.new
    for i in (0..623)
        t = mersenne.extract_number
        u = untemper4(t)
        u = untemper3(u)
        u = untemper2(u, i)
        u = untemper1(u)
        mt[i] = u
    end
    mersenne_clone = MersenneTwister.new(4) # seed is not important here - mt will be overridden anyway
    mersenne_clone.mt = mt
    s = 0
    for i in (0..623)
        a = mersenne.extract_number
        b = mersenne_clone.extract_number
        if a != b
	    s += 1
            puts "wrong !!!!!!!!!!!!!!!!!!!!!!!!!!"
        end
    end
    if s == 0
	puts "Mersenne Twister clone outputs the same numbers as the original Mersenne"
    end
end

def encrypt_mersenne(seed, text)
    mersenne = MersenneTwister.new(seed)
    keystream = ""
    calls_required = (text.length / 4) + 1
    for i in (1..calls_required)
        n = mersenne.extract_number
 	b = n.to_s(2)
	keystream += [b].pack("B*")
    end
    keystream = keystream[0..text.length-1]
    r = Util.xor(keystream, text)
    r
end

def encrypt_oracle(text)
    text = "B" * rand(8) + text
    seed = rand(2**16-1)
    r = encrypt_mersenne(seed, text)
    r
end

def challenge24()
    text = "A" * 14
    c = encrypt_oracle(text)
    prefix_length = c.length - text.length
    ptext = "C" * prefix_length + text
    for i in (0..2**16-1)
        r = encrypt_mersenne(i, ptext)
        if r[prefix_length..text.length] == c[prefix_length..text.length]
    	    d = encrypt_mersenne(i, c) # decrypt
	    puts "decrypted message (should be some Bs followed by A*14)"
	    puts d
	    break
	end
    end
end

def generate_token()
    seed = Time.new.to_i
    mersenne = MersenneTwister.new(seed)
    token = ""
    for i in (0..3)
        n = mersenne.extract_number
 	b = n.to_s(2)
	token += [b].pack("B*")
    end
    token
end

def challenge24_token()
    token = generate_token()
    time_now = Time.new.to_i
    for i in (0..9) # check "current times" in the last few seconds
        mersenne = MersenneTwister.new(time_now-i)
        guessed_token = ""
        for j in (1..token.length/4)
            n = mersenne.extract_number
 	    b = n.to_s(2)
	    guessed_token += [b].pack("B*")
        end
	if guessed_token == token
	    puts "The token has been found"
	    break
	end
    end
    token

end

#challenge17()
#challenge18()
#challenge19()
#challenge20()
#challenge21()
#challenge22()
#challenge23()
#challenge24()
challenge24_token()

