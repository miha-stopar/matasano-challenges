require 'openssl'
require_relative 'util'

def find_single_character_xored_string()
    f = File.open("set1chall4.txt", "r")
    f.each_line do |line|
	hex = line.chop
	key = Util.xor_with_all_chars_and_find_winner(hex)
	if key == nil
	    next
	end 
	hex_text = Util.xor_with_single_byte(hex, key)
	puts [hex_text].pack("H*")
    end
    f.close
end

def encrypt_with_repeating_key_xor(key, msg)
    hex1 = msg.unpack("H*")[0]
    repeat_key = msg.length / key.length + 1
    new_key = key * repeat_key
    hex2 = new_key.unpack("H*")[0]
    hex2 = hex2[0..hex1.length-1]
    r = Util.xor_two_hexes(hex1, hex2)   
    puts r
end

def hamming_distance(msg1, msg2)
    msg1_bits = msg1.unpack("B*")[0]
    msg2_bits = msg2.unpack("B*")[0]
    msg1_bits.length < msg1_bits.length ? len = msg1_bits.length : len = msg2_bits.length
    xored = Util.xor_two_binaries(msg1_bits, msg2_bits)
    b = Util.hex_to_binary(xored)
    distance = 0
    b.split("").each do |i|
      if i == "1" 
	distance += 1
      end
    end
    distance
end

def h(msg1_bits, msg2_bits)
    xored = Util.xor_two_binaries(msg1_bits, msg2_bits)
    b = Util.hex_to_binary(xored)
    distance = 0
    b.split("").each do |i|
      if i == "1" 
	distance += 1
      end
    end
    distance
end

def get_hamming_distances()
    distances = Hash.new
    for i in 2..40
	f = File.open("set1chall6.txt", "r")
	merged_lines = ""
        f.each_line do |line|
	    merged_lines += Util.base64_to_hex(line.chop)
	end
    	f.close
	j = 0
	k = 0
	averaged_dist = 0
	while j < merged_lines.length - 4*i do
	    msg1 = merged_lines[j..j + 2*i-1]
	    msg2 = merged_lines[j + 2*i..j + 4*i-1]
	    j += 2*i
	    m1 = [msg1].pack("H*")
	    m2 = [msg2].pack("H*")
	    dist = hamming_distance(m1, m2) / i.to_f
	    averaged_dist += dist
	    k += 1
	end
	distances[i] = averaged_dist / k.to_f
    end

    return distances.min_by(&:last)[0]
end

def build_blocks(key_length)
    blocks = Hash.new
    f = File.open("set1chall6.txt", "r")
    c = 0
    for i in 0..key_length-1
	blocks[i] = ""
    end
    count = 0
    f.each_line do |line|
	# TODO: in hex
	b = Util.base64_to_hex(line.chop)
	(0..b.length-2).step(2) do |i|
	    blocks[c % key_length] += b[i..i+1]
	    c += 1
	end
	count += 1
    end
    f.close
    blocks
end

def from_blocks(blocks)
    m = ""
    ind = 0
    exit_loop = false
    while true do
	for i in 0..blocks.length-1
	    if ind == blocks[i].length
	        exit_loop = true
                break
	    end
	    m += blocks[i][ind]
	end
	if exit_loop
	    break
	end
	ind += 1
    end
    m
end

def challenge1()
    puts "challenge 1..."
    b = Util.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    puts "given hex string is converted to base64: ", b
    puts "it should be: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    puts ""
end

def challenge2()
    puts "challenge 2..."
    s1 = "1c0111001f010100061a024b53535009181c"
    s2 = "686974207468652062756c6c277320657965"
    r = Util.xor_two_hexes(s1, s2)
    puts "xoring two given strings produces: ", r
    puts "it should be: 746865206b696420646f6e277420706c6179"
    puts ""
end

def challenge3()
    puts "challenge 3..."
    h1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    key = Util.xor_with_all_chars_and_find_winner(h1)
    puts key
    hex_text = Util.xor_with_single_byte(h1, key)
    msg = [hex_text].pack("H*")
    puts "decrypted message:"
    puts msg
    puts "decrypted message should be: ", "Cooking MC's like a pound of bacon"
end

def challenge4()
    find_single_character_xored_string()
end

def challenge5()
    s = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    encrypt_with_repeating_key_xor("ICE", s)
end

def challenge6()
    # just verifying that hamming_distance works correctly
    s1 = "this is a test"
    s2 = "wokka wokka!!!"
    d = hamming_distance(s1, s2)
    puts d

    key_length = get_hamming_distances()
    puts "key length:"
    puts key_length

    blocks = build_blocks(key_length)
    single_byte_key = Util.xor_with_all_chars_and_find_winner(blocks[1])

    key = Hash.new
    for j in 0..blocks.length-1
        single_byte_key = Util.xor_with_all_chars_and_find_winner(blocks[j])
	key[j] = single_byte_key
	if single_byte_key == nil
	    break
	end
    end
    puts key
    dblocks = Hash.new
    for j in 0..blocks.length-1
	hex_text = Util.xor_with_single_byte(blocks[j], key[j])
	dblocks[j] = [hex_text].pack("H*")
    end
    m = from_blocks(dblocks)
    puts m
end

def challenge7()
    puts "challenge 7..."
    c = File.read("set1chall7.txt")
    c = c.unpack("m").join()
    decipher= OpenSSL::Cipher.new("AES-128-ECB")
    decipher.decrypt
    decipher.key = "YELLOW SUBMARINE"
    plain = decipher.update(c) + decipher.final
    puts plain
    puts ""
    puts "The decrypted message should end as: "
    puts "Play that funky music"
end

def challenge8()
    puts "challenge 8..."
    f = File.open("set1chall8.txt", "r")
    texts = Array.new
    f.each_line do |line|
	texts.push(line.chop)
    end
    f.close
    for text in texts
	c = Util.count_repeated_blocks(text, 32) # 32 because it is hex
	if c > 0
	    puts "the following text found to be AES ECB encrypted:"
	    puts text
	end
    end
end

#challenge1()
#challenge2()
#challenge3()
#challenge4()
#challenge5()
#challenge6()
#challenge7()
challenge8()


