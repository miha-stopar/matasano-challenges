require_relative 'mersenne_twister'

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

t = "10110111010111100111111001110010".to_i(2)
t = "10110111010111100111111001011001".to_i(2)
#t = 2366756407
t = 2645014833

#t = t ^ (t >> 11)
#puts t.to_s(2)

#t = t ^ ((t << 7) & 2636928640)
#u = untemper2(t)
#u = untemper1(t)
#puts u.to_s(2)

#__END__
#t = t ^ ((t << 15) & 4022730752)
#t = t ^ (t >> 18)

#u = untemper4(t)
#u = untemper3(u)
#u = untemper2(u)
#u = untemper1(u)
#puts u.to_s(2)


#mersenne = MersenneTwister.new(Time.now.to_i)
mersenne = MersenneTwister.new(2)
mt = Array.new
for i in (0..623)
    t = mersenne.extract_number
    u = untemper4(t)
    u = untemper3(u)
    u = untemper2(u, i)
    u = untemper1(u)
    if mersenne.mt[i] != u
        puts "mt not correct !!!!!!!!!!"
    end
    mt[i] = u
end
#__END__
mersenne_clone = MersenneTwister.new(4) # seed is not important here - mt will be overridden anyway
mersenne_clone.mt = mt

for i in (0..623)
    a = mersenne.extract_number
    b = mersenne_clone.extract_number
    if a != b
        puts "wrong !!!!!!!!!!!!!!!!!!!!!!!!!!"
    end
end




