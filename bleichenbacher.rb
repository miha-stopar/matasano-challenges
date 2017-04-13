# still sometimes fails to_bn.mod_exp (see rsa.rb:46) with segmentation error
# for testing: make in rsa.rb use always the same p and q, and use the same padded_m in prepare_some_ciphertext

require 'digest/sha1'
require 'openssl'
require_relative 'rsa'
require_relative 'util'

class RsaOracle
    def initialize()
        @rsa = RSA.new(512)
    end

    def get_parameters()
	return @rsa.e, @rsa.n
    end

    def isPKCSconforming(c, bigB)
        m = @rsa.decrypt(c) 
        #if m.length == 31 and m[0] == 2.chr # the first 0.chr does not have effect
	num = m.unpack("H*").join.to_i(16)
	if num >= 2 * bigB and num < 3 * bigB
	    return true
	else
	    return false
	end 
    end

def prepare_some_ciphertext(bigB)
    	m = "kick it, CC"
        k = @rsa.n.to_i.to_s(16).length / 2 # number of bytes of n
	d = k - m.length - 3 # how long should be random padding string 
	#padded_m = 0.chr + 2.chr + 11.chr * d + 0.chr + m # should be random instead of "11" * d
	#padded_m = 0.chr + 2.chr + 94.chr * d + 0.chr + m # this is 64..., usually leads to 64-72
	#padded_m = 0.chr + 2.chr + 250.chr * d + 0.chr + m # should be random instead of "250" * d

	r = d.times.map{Random.rand(256)}
	#r = [225, 86, 248, 117, 70, 221, 28, 162, 194, 210, 70, 123, 178, 28, 140, 161, 76, 145, 232, 194, 164, 35, 113, 199, 7, 210, 114, 111, 22, 98, 99, 60, 139, 73, 234, 30, 174, 214, 152, 101, 227, 116, 73, 248, 180, 89, 153, 163, 78, 12, 138, 104, 195, 30, 136, 238, 224, 105, 103, 191, 183, 246, 114, 2, 198, 17, 94, 66, 240, 25, 10, 85, 72, 156, 193, 143, 83, 159, 236, 71, 148, 178, 77, 218, 61, 157, 25, 251, 168, 38, 167, 158, 188, 13, 254, 146, 8, 159, 136, 61, 156, 215, 0, 106, 42, 185, 83, 4, 159, 115, 146, 48, 136, 233]
	#r = [185, 235, 116, 96, 82, 183, 253, 33, 232, 88, 55, 180, 151, 244, 114, 155, 35, 53, 229, 121, 73, 10, 98, 177, 101, 6, 68, 104, 183, 140, 126, 223, 8, 120, 48, 12, 241, 244, 250, 210, 213, 97, 170, 140, 96, 54, 7, 138, 24, 224, 217, 112, 87, 10, 160, 142, 88, 21, 246, 13, 129, 128, 99, 25, 37, 104, 89, 214, 44, 138, 69, 96, 98, 22, 243, 203, 36, 199, 199, 85, 227, 173, 220, 5, 104, 147, 111, 129, 222, 99, 3, 157, 76, 17, 15, 76, 91, 251, 121, 183, 147, 233, 84, 70, 139, 21, 50, 221, 88, 66, 202, 38, 68, 106]
	#r = [205, 236, 140, 12, 246, 147, 188, 152, 86, 217, 232, 110, 18, 36, 31, 248, 58, 53, 80, 68, 214, 148, 235, 189, 232, 94, 109, 153, 229, 238, 109, 9, 112, 222, 24, 166, 88, 11, 89, 227, 13, 202, 97, 186, 200, 155, 152, 1, 81, 253, 39, 224, 166, 109, 220, 244, 156, 23, 154, 66, 49, 72, 178, 13, 10, 132, 157, 118, 16, 72, 88, 206, 20, 29, 46, 116, 227, 152, 154, 171, 218, 21, 138, 31, 87, 50, 143, 171, 164, 215, 78, 102, 145, 111, 159, 208, 105, 197, 166, 116, 111, 63, 17, 237, 233, 21, 81, 199, 118, 71, 187, 155, 177, 147]
	print r
	puts "\n"
	r = r.map{|x| x.chr}
	padded_m = 0.chr + 2.chr + r.join("") + 0.chr + m
	c = @rsa.encrypt(padded_m)
	conforming = isPKCSconforming(c, bigB)
	return c, padded_m
    end
end

def get_rs(s_i, a, b, n, bigB)
    r_min = s_i*a/n
    r_max = s_i*b/n

    if s_i * a > r_min * n + 3*bigB
	r_min += 1
    end
    if s_i * b < r_max * n + 2*bigB
	r_max -= 1
    end
    return (r_min..r_max)
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

def check_how_probable(start, r_cand, other_r_candidates, e, n, c, bigB, oracle, padded_m_num, a, b, cycles)
    # returns a number for the candidate interval - the bigger the number is, the bigger
    # is the probability that this is the right interval
    puts "------------------"
    conforming_num = 0
    accesses = 0
    for i in (1..cycles)   
	r = r_cand + i
        start = (r * n + 3*bigB)/b
        if start.class == Array
            start = start[0]
            start = start.to_i
        end
        if start * b < r * n + 2*bigB
	    start += 1
        end
	#puts start*(b-a)/Float(bigB)
	skip = false
        rs = get_rs(start, a, b, n, bigB)
        if rs.to_a == [] # when (start * a, start * b) does not intersect conforming interval
	    skip = true
        end
	
	if start*a < r*n + 3*bigB and start*b >= r*n+ 2*bigB and not skip
	    c1 = (start**e * c) % n
	    conforming = oracle.isPKCSconforming(c1, bigB)
	    accesses += 1
	    if conforming
	        conforming_num += 1
	    else
		if start*a > r*n + 2*bigB or start*b < r*n+ 3*bigB
		    if start*a > r*n + 2*bigB and start*b > r*n + 3*bigB
			a = (r*n+3*bigB)/start
		    end
		    if start*a < r*n + 2*bigB and start*b < r*n + 3*bigB
			b = (r*n+2*bigB)/start
		    end
		end
	    end
	end

	skip = false
	rs = get_rs(start+1, a, b, n, bigB)
        if rs.to_a == [] # when (start * a, start * b) does not intersect conforming interval
	    skip = true
        end

	if (start+1)*a < r*n + 3*bigB and (start+1)*b >= r*n+ 2*bigB and not skip
	    m1 = [(start+1)*a, r*n+2*bigB].max
	    m2 = [(start+1)*b, r*n+3*bigB-1].min
	    intersection_this = m2 - m1

	    c1 = ((start+1)**e * c) % n
	    conforming = oracle.isPKCSconforming(c1, bigB)
	    accesses += 1
	    if conforming
	        conforming_num += 1
	    else
		if (start+1)*a > r*n + 2*bigB or (start+1)*b < r*n+ 3*bigB
		    if (start+1)*a > r*n + 2*bigB and (start+1)*b > r*n + 3*bigB
			a = (r*n+3*bigB)/(start+1)
		    end
		    if (start+1)*a < r*n + 2*bigB and (start+1)*b < r*n + 3*bigB
			b = (r*n+2*bigB)/(start+1)
		    end
		end
	    end

	end
    end
    return conforming_num, accesses
end

def step1(start, e, n, c, bigB, oracle, padded_m_num, a, b)
    accesses = 0
    attempt = 0
    for s_i in (start..start+10000000)
	rs = get_rs(s_i, a, b, n, bigB)
	if rs.to_a == [] # just realized this is actually the same as skipping holes in Bardou at al.
	    next
	end
        c1 = (s_i**e * c) % n

	conforming = oracle.isPKCSconforming(c1, bigB)
	accesses += 1
	if conforming
 	    results = {}
	    real_r = nil
	    if rs.to_a.length > 1
	        puts rs
                for r in rs
		    min = (r*n + 2*bigB) / s_i
		    max = (r*n + 3*bigB - 1) / s_i
		    puts "++++"
		    puts min
		    puts max
		    cycles = 20
		    taccesses = 0
	            num, accs = check_how_probable(s_i, r, rs.to_a - [r], e, n, c, bigB, oracle, padded_m_num, min, max, cycles)
		    accesses += accs 
		    results[r] = num
	        end
	        puts results
		sorted_results = results.sort_by {|_key, value| value}.reverse
		puts sorted_results
		puts "=="
		print sorted_results
		if sorted_results[0][1] == sorted_results[1][1]
		    abort("check_how_probable could not distinguish between candidate intervals")
		end
		real_r = results.sort_by {|_key, value| value}.reverse[0][0]
	    else
		real_r = rs.to_a[0]
	    end
	    puts "conforming: " + s_i.to_s + " " + real_r.to_s
	    min = (real_r*n + 2*bigB) / s_i
	    max = (real_r*n + 3*bigB - 1) / s_i
	    return min, max, real_r, s_i, accesses
	end
    end
end

def submit_ciphertext(start, e, n, c, bigB, oracle, padded_m_num, a, b, bla = false)
    # it submits ciphertext and returns a new interval when the ciphertext is PKCS compliant and
    # and two intervals when the ciphertext is not PKCS compliant (the plaintext is
    # located in one of these two)
    accesses = 0
    attempt = 0

    s_i = start
    r = start * b / n
    c1 = (s_i**e * c) % n
   	
    conforming = oracle.isPKCSconforming(c1, bigB)
    accesses += 1
    if conforming
        if bla
            puts "conforming: " + s_i.to_s + " " + r.to_s
        end
        min = (r*n + 2*bigB) / s_i
        max = (r*n + 3*bigB - 1) / s_i
        if min < a
            min = a
        end
        if max > b
            max = b
        end

        if min > padded_m_num or max < padded_m_num
  	    puts "===="
	    puts s_i
	    puts c
    	    puts "--"
	    puts a
   	    puts b
	    puts min
	    puts max
	    # this happened sometimes when results of check_how_probable were not
	    # sufficient to determine the right interval
	    abort("hmmmmmmmmmmmmmmmmmm")
	 end
        return true, [[min, max]]
    else
        if bla
            puts "non conforming: " + s_i.to_s + " " + r.to_s
        end
        m1 = r * n + 2*bigB
        m2 = r * n + 3*bigB - 1
        f1 = s_i * a
        f2 = s_i * b
        bounds = []
        if f1 < m1
            min1 = f1 / s_i
            max1 = m1 / s_i
            bounds.push([min1, max1])
        end
        if f2 > m2
            min2 = m2 / s_i
            max2 = f2 / s_i
            bounds.push([min2, max2])
        end
        good_candidate = false # idiot, here might not be good candidates (if from ...two1)
        for boo in bounds
  	    if boo[0] <= padded_m_num and padded_m_num <= boo[1]
	        good_candidate = true
	    end
	end
	if false
        #if bla
   	    if not good_candidate
	        puts "================="
	        puts r
	        puts s_i
   	        puts a
	        puts "---"
	        puts b
	        puts "---"
	        puts bounds
	        abort("blablabla")
	    end
	end
	if bounds.length == 1
            min = bounds[0][0]
            max = bounds[0][1]
            return false, [[min, max]]
	end
	return false, bounds
    end
end

def choose_between_two3(start, e, n, c, bigB, oracle, padded_m_num, r, bounds)
	#puts "-----------------"
	#puts padded_m_num
	#puts "++"
	#puts bounds
	#puts "++"
	accesses = 0
	a1, b1 = bounds[0]
	a2, b2 = bounds[1]
	if a1 == b1
   	    b1 += 1 # todo
	end
	if a2 == b2
	    b2 += 1 # todo
	end
	j = 0
	while true
	    #j += 1
	    #puts "-----------"
	    #puts a1
	    #puts b1
	    #puts "--"
	    #puts a2
	    #puts b2
	    if b1 - a1 < 10
		f, accs = eliminate(a1, b1, bigB, e, c, n, oracle)
		accesses += accs
		if f != nil
		    return [[f,f]], accesses
		end
	    else
	        tmp_r1, tmp_start1 = find_rs_pair(a1, b1, bigB, n, 1)
		#puts "==1"
		#puts tmp_r1
		#puts tmp_start1
	    end
	    if b2-a2 < 10
		f, accs = eliminate(a2, b2, bigB, e, c, n, oracle)
		accesses += accs
		if f != nil
		    #return f, accesses
		    return [[f,f]], accesses
		end
	    else
	        tmp_r2, tmp_start2 = find_rs_pair(a2, b2, bigB, n, 1)
		#puts "==2"
		#puts tmp_r2
		#puts tmp_start2
	    end

	    if tmp_start1 != nil and tmp_start1 * b1 > tmp_r1 * n + 2*bigB and tmp_start1 * a1 < tmp_r1 * n + 3*bigB
		temp_r = tmp_start1 * b2 / n
		suspicious = false
	    	if tmp_start1 * b2 > temp_r * n + 2*bigB and tmp_start1 * a2 < temp_r * n + 3*bigB
		    suspicious = true
		    puts "suspicous 1"
		    puts a1
	    	    puts b1
		    puts "-"
	    	    puts tmp_r1
		    puts "-"
	    	    puts tmp_start1

		end
		#if j > 0
		if false
	            min = [tmp_start1*a1, tmp_r1*n+2*bigB].max
	            max = [tmp_start1*b1, tmp_r1*n+3*bigB].min
		    puts "-------10"
	    	    puts a1
	    	    puts b1
		    puts "-"
	    	    puts tmp_r1
		    puts "-"
	    	    puts tmp_start1
	            #puts Float(bigB)/(max-min)
	            #puts (tmp_start1*b1 - tmp_start1*a1)/Float(bigB)
		end
		if not suspicious
		    conforming, n_bounds = submit_ciphertext(tmp_start1, e, n, c, bigB, oracle, padded_m_num, a1, b1)
		    accesses += 1
		    if n_bounds[0][0] == a1 and n_bounds[0][1] == b1
			#puts n_bounds
			#abort("adfa 1")
		    end
		    if conforming
	    	        return n_bounds, accesses
		    elsif n_bounds.length == 1
			#puts n_bounds
			a1 = n_bounds[0][0]
			b1 = n_bounds[0][1]
		    end
		end
	    end
	   
	    if tmp_start2 != nil and tmp_start2 * b2 > tmp_r2 * n + 2*bigB and tmp_start2 * a2 < tmp_r2 * n + 3*bigB
		temp_r = tmp_start2 * b1 / n
		suspicious = false
	    	if tmp_start2 * b1 > temp_r * n + 2*bigB and tmp_start2 * a1 < temp_r * n + 3*bigB
		    suspicious = true
		    puts "suspicous 2"
		    puts a2
	            puts b2
		    puts "-"
	            puts tmp_r2
		    puts "-"
	            puts tmp_start2
		end
		#if j > 0
		if false
		    puts "-------20"
	            min = [tmp_start2*a2, tmp_r2*n+2*bigB].max
	            max = [tmp_start2*b2, tmp_r2*n+3*bigB].min
	            puts a2
	            puts b2
		    puts "-"
	            puts tmp_r2
		    puts "-"
	            puts tmp_start2
	            #puts Float(bigB)/(max-min)
	            puts (tmp_start2*b2 - tmp_start2*a2)/Float(bigB)
		end

		if not suspicious
		    conforming, n_bounds = submit_ciphertext(tmp_start2, e, n, c, bigB, oracle, padded_m_num, a2, b2)
		    accesses += 1
		    if n_bounds[0][0] == a2 and n_bounds[0][1] == b2
			#puts n_bounds
			#abort("adfa 2")
		    end
		    if conforming
	    	        return n_bounds, accesses
		    elsif n_bounds.length == 1
			#puts n_bounds
			a2 = n_bounds[0][0]
			b2 = n_bounds[0][1]
		    end
		end
	    end

	    #tmp_r1 += 1
	    #tmp_r2 += 1
	end
	if true
	    puts "nooooooot gooooooooooooooooooooooood!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	    abort("does not work")
	end
end

def choose_between_two1(start, e, n, c, bigB, oracle, padded_m_num, r, bounds)
	accesses = 0
	a1, b1 = bounds[0]
	a2, b2 = bounds[1]
	if a1 == b1
	    #puts a1
	    #puts a2
	    #puts b2
   	    b1 += 1 # todo
	end
	if a2 == b2
	    #puts a2
	    #puts a1
	    #puts b2
	    b2 += 1 # todo
	    #puts abort("asdfsadf2")
	end
	# experimenting 1:
	s1 = 2*bigB / (b1-a1)
	#s1 = bigB / (b1-a1)
	tmp_r1 = s1*b1 / n
	s1 = 2*bigB / (b2-a2)
	#s1 = bigB / (b2-a2)
	tmp_r2 = s1*b2 / n

	#puts "==========================================="
	#puts r
	#puts tmp_r1
	#puts tmp_r2
	#test = ((r+1) * n + 3*bigB)/b1
	#l = bigB/(test*b1 - test*a1)
	#puts l

	j = 0
	good_candidate = ((a1 <= padded_m_num and padded_m_num <= b1) or (a2 <= padded_m_num and padded_m_num <= b2))
	if not good_candidate
	    puts "----------------------"
	    puts a1
	    puts b1
	    puts a2
	    puts b2
	    abort("tralalalala")
	end
	while true
	    j += 1
	    tmp_start1 = (tmp_r1 * n + 3*bigB)/b1
	    if tmp_start1 * b1 < tmp_r1 * n + 2 * bigB
                tmp_start1 += 1
            end
	    tmp_start11 = tmp_start1 + 1

	    tmp_start2 = (tmp_r2 * n + 3*bigB)/b2
	    if tmp_start2 * b2 < tmp_r2 * n + 2 * bigB
                tmp_start2 += 1
            end
	    tmp_start21 = tmp_start2 + 1

	    if tmp_start1 * b1 > tmp_r1 * n + 2*bigB and tmp_start1 * a1 < tmp_r1 * n + 3*bigB
		temp_r = tmp_start1 * b2 / n
		suspicious = false
	    	if tmp_start1 * b2 > temp_r * n + 2*bigB and tmp_start1 * a2 < temp_r * n + 3*bigB
		    suspicious = true
		    puts "suspicous 1"
		    puts a1
	    	    puts b1
		    puts "-"
	    	    puts tmp_r1
		    puts "-"
	    	    puts tmp_start1

		end
		#if j > 0
		if false
	            min = [tmp_start1*a1, tmp_r1*n+2*bigB].max
	            max = [tmp_start1*b1, tmp_r1*n+3*bigB].min
		    puts "-------10"
	    	    puts a1
	    	    puts b1
		    puts "-"
	    	    puts tmp_r1
		    puts "-"
	    	    puts tmp_start1
	            #puts Float(bigB)/(max-min)
	            puts (tmp_start1*b1 - tmp_start1*a1)/Float(bigB)
		end
		if not suspicious
		    conforming, n_bounds = submit_ciphertext(tmp_start1, e, n, c, bigB, oracle, padded_m_num, a1, b1)
		    accesses += 1
		    if conforming
	    	        return n_bounds, accesses
		    end
		end
	    end
	   
	    if tmp_start11 * b1 > tmp_r1 * n + 2*bigB and tmp_start11 * a1 < tmp_r1 * n + 3*bigB
		temp_r = tmp_start11 * b2 / n
		suspicious = false
	    	if tmp_start11 * b2 > temp_r * n + 2*bigB and tmp_start11 * a2 < temp_r * n + 3*bigB
		    suspicious = true
		    puts "suspicous 11"
		    puts a1
	    	    puts b1
		    puts "-"
	    	    puts tmp_r1
		    puts "-"
	    	    puts tmp_start11
		end
		#if j > 0
		if false
		    puts "-------11"
		    min = [tmp_start11*a1, tmp_r1*n+2*bigB].max
	            max = [tmp_start11*b1, tmp_r1*n+3*bigB].min
	    	    puts a1
	    	    puts b1
		    puts "-"
	    	    puts tmp_r1
		    puts "-"
	    	    puts tmp_start11
	            #puts Float(bigB)/(max-min)
	            puts (tmp_start11*b1 - tmp_start11*a1)/Float(bigB)
		end

		if not suspicious
		    conforming, n_bounds = submit_ciphertext(tmp_start11, e, n, c, bigB, oracle, padded_m_num, a1, b1)
		    accesses += 1
		    if conforming
	    	        return n_bounds, accesses
		    end
		end
	    end
 
	    if tmp_start2 * b2 > tmp_r2 * n + 2*bigB and tmp_start2 * a2 < tmp_r2 * n + 3*bigB
		temp_r = tmp_start2 * b1 / n
		suspicious = false
	    	if tmp_start2 * b1 > temp_r * n + 2*bigB and tmp_start2 * a1 < temp_r * n + 3*bigB
		    suspicious = true
		    puts "suspicous 2"
		    puts a2
	            puts b2
		    puts "-"
	            puts tmp_r2
		    puts "-"
	            puts tmp_start2
		end
		#if j > 0
		if false
		    puts "-------20"
	            min = [tmp_start2*a2, tmp_r2*n+2*bigB].max
	            max = [tmp_start2*b2, tmp_r2*n+3*bigB].min
	            puts a2
	            puts b2
		    puts "-"
	            puts tmp_r2
		    puts "-"
	            puts tmp_start2
	            #puts Float(bigB)/(max-min)
	            puts (tmp_start2*b2 - tmp_start2*a2)/Float(bigB)
		end

		if not suspicious
		    conforming, n_bounds = submit_ciphertext(tmp_start2, e, n, c, bigB, oracle, padded_m_num, a2, b2)
		    accesses += 1
		    if conforming
	    	        return n_bounds, accesses
		    end
		end
	    end

	    if tmp_start21 * b2 > tmp_r2 * n + 2*bigB and tmp_start21 * a2 < tmp_r2 * n + 3*bigB
		temp_r = tmp_start21 * b1 / n
		suspicious = false
	    	if tmp_start21 * b1 > temp_r * n + 2*bigB and tmp_start21 * a1 < temp_r * n + 3*bigB
		    suspicious = true
		    puts "suspicous 21"
		    puts a2
	    	    puts b2
		    puts "-"
	    	    puts tmp_r2
		    puts "-"
	    	    puts tmp_start21
		end
		#if j > 0
		if false
		    puts "-------21"
		    min = [tmp_start21*a2, tmp_r2*n+2*bigB].max
	            max = [tmp_start21*b2, tmp_r2*n+3*bigB].min
	    	    puts a2
	    	    puts b2
		    puts "-"
	    	    puts tmp_r2
		    puts "-"
	    	    puts tmp_start21
	            #puts Float(bigB)/(max-min)
	            puts (tmp_start21*b2 - tmp_start21*a2)/Float(bigB)
		end

		if not suspicious
		    conforming, n_bounds = submit_ciphertext(tmp_start21, e, n, c, bigB, oracle, padded_m_num, a2, b2)
		    accesses += 1
		    if conforming
	    	        return n_bounds, accesses
		    end
		end
	    end

	    tmp_r1 += 1
	    tmp_r2 += 1
	end
	if true
	    puts "nooooooot gooooooooooooooooooooooood!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	    abort("does not work")
	end
end

def eliminate(ta, tb, bigB, e, c, n, oracle)
    accesses = 0
    for t in (ta..tb)
	s = bigB
        r = s * t / n
	while true
	    if s*t < r * n + 2*bigB
	        s = (r * n + 2*bigB)/t
	        if s*t < r * n + 2*bigB
		    s += 1
		end
	    end
	    if s*t > r * n + 3*bigB
		r += 1
		next
	    end
	    if s * t > r * n + 2*bigB and s * t < r * n + 3*bigB
                c1 = (s**e * c) % n
	        conforming = oracle.isPKCSconforming(c1, bigB)
	        accesses += 1
	        if conforming
		    #puts "===="
		    #puts t
		    #puts accesses
		    return t, accesses
	        else
		    #puts "not: " + t.to_s
		    break
	        end
	    end
	    r += 1
	end
    end
    return nil, accesses
end

def trim(oracle, n, e, c, padded_m_num, bigB, a, b)
    new_a = a
    new_b = b
    accs = 0
    found = false
    exitLoop = false	
    j = 0
    max_t = 4096
    best_improvement_a = nil
    best_improvement_b = nil
    bla_counter = 0
    for t in (2..max_t)
	min_u = (2*t/3).to_i
	max_u = (1.5 * t).to_i
	u_values = (min_u..max_u) 
	if true
	    if t > 50
		u_values = [t-10, t+10]
	        #min_u = t-2
	        #max_u = t+2
	    end
	end
	if exitLoop
	    break
	end
        for u in u_values
	    if u == t
	 	next
	    end
	    #if not experimenting and j == 1000
	    if j == 1000
		exitLoop = true
		break
	    end
            gcd, x, y = Util.xgcd(t, u, [1,0], [0,1])
            if gcd == 1
		t_inv = Util.invmod(n, t)
		useful = true
    	        if new_b * u / t < 2*bigB or new_a * u / t >= 3*bigB
		    # by Proposition we know m*u*t_inv % n = m * u / t
		    # and we could gain info only from PKCS compliant m*u*t_inv % n messages, thus
		    # each message which could bring info will meet this if condition
		    useful = false
		end
		a1 = new_a*u*t_inv
		b1 = new_b*u*t_inv
		r_min = a1 / n
    		r_max = b1 / n

    		if a1 > r_min * n + 3*bigB
		     r_min += 1
    		end
    		if b1 < r_max * n + 2*bigB
		    r_max -= 1
    		end

	        if r_max < r_min
		    if useful
			#abort("might help 1")
		    end
		end

		if not useful
		    bla_counter += 1
		    next
		end

		c1 = ((u * t_inv)**e * c) % n

		if 2*bigB * t/u < new_a and 3*bigB * t/u > new_b
		    next	
		end
		if not useful 
		    #abort("might help")
		end
		#puts t/Float(u)
		conforming = oracle.isPKCSconforming(c1, bigB)
	    	j += 1
		accs += 1
		if conforming
		    if not useful
		        abort("strange 1")
		    end

		    if padded_m_num * u / t >= n
		        abort("strange 2")
		    end
		    #puts u * t_inv
		    ac = 2*bigB * t/u
		    bc = 3*bigB * t/u
		    if ac > new_a
			new_a = ac
			best_improvement_a = j

			puts "accesses: " + j.to_s + "; u: " + u.to_s + " t: " + t.to_s
			puts bigB / Float(new_b - new_a)
		        puts "___________"
			if bigB / (new_b - new_a) > 6
			    found = true
			    puts bigB / (new_b - new_a)
			    puts "breaking a ......"
			    break
			end
		    end
		    if bc < new_b
			new_b = bc
			best_improvement_b = j

			puts "accesses: " + j.to_s + "; u: " + u.to_s + " t: " + t.to_s
			puts bigB / Float(new_b - new_a)
		        puts "___________"
			if bigB / (new_b - new_a) > 6
			    found = true
			    puts bigB / (new_b - new_a)
			    puts "breaking b ......"
			    break
			end
		    end
		end
            end
        end
	if found
	    puts "==="
	    break
	end
    end
    puts "----------------+++++++++++++++++++++--------------------"
    puts bla_counter
    return new_a, new_b, accs, best_improvement_a, best_improvement_b
end

def find_rs_pair(a, b, bigB, n, coeff=2)
    s_tmp = coeff*bigB/(b-a)
    r = s_tmp * b / n
	
    intersection = 0
    r_best = nil
    s_best = nil
    r_cand = r
    pairs = []
    best_r = 0
    best_s = 0
    while true
	r_cand += 1
        start = (r_cand * n + 2*bigB)/b
        if start.class == Array
            start = start[0]
            start = start.to_i
        end
	start += 1
	#if start * (b-a) < 1.5 * bigB or start * (b-a) > 2.5 * bigB
	#    next
	#end
        intersection = 0
	if (start * b >= r_cand*n + 2*bigB and start * a < r_cand*n + 3*bigB)
	    #puts "!!"
	    min = [start*a, r_cand*n+2*bigB].max
	    max = [start*b, r_cand*n+3*bigB].min
	    intersection_part = (max-min)/Float(bigB)
	    #puts intersection_part
	    #puts (start*b - start*a)/Float(bigB)
	    if intersection_part > intersection and intersection_part < 1
		# intersection_part < 1 to have "overflow" only on one side
		intersection = intersection_part
		best_r = r_cand
	  	best_s = start
	    end
	end

	start += 1
	if (start * b >= r_cand*n + 2*bigB and start * a < r_cand*n + 3*bigB)
	    #puts "!!!"
	    min = [start*a, r_cand*n+2*bigB].max
	    max = [start*b, r_cand*n+3*bigB].min
	    intersection_part = (max-min)/Float(bigB)
	    #puts intersection_part
	    #puts (start*b - start*a)/Float(bigB)
	    if intersection_part > intersection and intersection_part < 1
		intersection = intersection_part
		best_r = r_cand
	  	best_s = start
	    end
	end
	if intersection > 0.5
	    return best_r, best_s
	end
    end
    return nil, nil
end

def choose_best_rs_pair(a, b, bigB, n, r, around=0)
    #s_tmp = coeff*bigB/(b-a)
    #r = s_tmp * b / n
	
    intersection = 0
    r_best = nil
    s_best = nil
    #for r_cand in (r-5..r+5)
    for r_cand in (r-around..r+around)
        start = (r_cand * n + 2*bigB)/b
        if start.class == Array
            start = start[0]
            start = start.to_i
        end
	# r_cand * b is now smaller than r_cand*n + 2*bigB:
	start += 1
	if start * (b-a) < 1.5 * bigB or start * (b-a) > 2.5 * bigB
	    next
	end
	ok = (start * b >= r_cand*n + 2*bigB and start * a < r_cand*n + 3*bigB)
	#puts "========"
	#puts r_cand
	#puts start
	#puts a
	#puts b
	#puts "==="
	if ok
	    m1 = [start*a, r_cand*n+2*bigB].max
	    m2 = [start*b, r_cand*n+3*bigB-1].min
	    intersection_tmp = m2 - m1
	    if intersection_tmp > intersection
	        r_best = r_cand
	        s_best = start
	        intersection = intersection_tmp
	    end
	end

	start += 1
	ok1 = (start * b >= r_cand*n + 2*bigB and start * a < r_cand*n + 3*bigB)
	if ok1
	    m1 = [start*a, r_cand*n+2*bigB].max
	    m2 = [start*b, r_cand*n+3*bigB-1].min
	    intersection_tmp = m2 - m1
	    if intersection_tmp > intersection
	        r_best = r_cand
	        s_best = start
	        intersection = intersection_tmp
	    end 
	end
    end

    return r_best, s_best
end

def find_plaintext(oracle, n, e, c, padded_m_num, bigB, experimenting=false)
    a = 2 * bigB
    b = 3 * bigB - 1

    new_a, new_b, trimming_accs, best_improvement_a, best_improvement_b = trim(oracle, n, e, c, padded_m_num, bigB, a, b)
    #new_a = a
    #new_b = b
    #trimming_accs = 0
    #best_improvement_a = 0
    #best_improvement_b = 0

    o_accesses = trimming_accs
    a = new_a
    b = new_b
    puts "-----------------------------"
    puts "trimming accesses:"
    puts trimming_accs

    #start = (n+2*bigB)/(3*bigB-1)
    start = (n+2*bigB)/b
    if start.class == Array
        start = start[0]
        start = start.to_i
    end
    min = a
    max = b

    puts "n:"
    puts n
    puts "bigB:"
    puts bigB
    puts "plaintext:"
    puts padded_m_num
    puts "a:"
    puts a
    puts "b:"
    puts b
    #abort("after trimming")

    verifying = get_verifying(padded_m_num, n, bigB)
    p verifying

    a, b, r, s, accesses = step1(start, e, n, c, bigB, oracle, padded_m_num, a, b)
    if verifying.length > 0
        if s != verifying[0][0]
	    abort("wronggggggggggggggggggggggggg")
	end
    end
    o_accesses += accesses
    puts a
    puts b
    puts accesses
    puts o_accesses
    puts "+++++++++++++++++++++++++"
    
    while true	
        s_tmp = 2*bigB/(b-a)
        r = s_tmp * b / n

	r, start = choose_best_rs_pair(a, b, bigB, n, r, around=5)

	conforming, bounds = submit_ciphertext(start, e, n, c, bigB, oracle, padded_m_num, a, b)
	#puts "---"
	#puts bounds
	if bounds.length == 1
	    #puts "reduced"
	    min = bounds[0][0]
	    max = bounds[0][1]
	    # sometimes (when a and b are close) submit_ciphertext does not return improved bounds because
	    # for example [start * a > r*n + 2*bigB, start * a < r*n + 3*bigB, 
	    # start * b > r*n + 3*bigB, the message start * padded_m_num % n is not PKCS compliant]
	    # in this case the new a should be (r*n+3*bigB)/start, however this might be the 
	    # same as a when start*(a+1) > r*n + 3*bigB (start*a close to r*n + 3*bigB - the 
	    # intersection of [s*a, s*b] and [r*n+2*bigB, r*n+3*bigB-1] is small)
	    not_improved = (min == a and max == b)
	    a = min
	    b = max
	    if padded_m_num < a or padded_m_num > b
	        abort("this should not happen")
	    end
	    #if b-a < 10
	    if not_improved
		f, accesses = eliminate(a, b, bigB, e, c, n, oracle)
		puts accesses
		o_accesses += accesses
	 	a = f
		b = f
	    end
	end
	good_candidate = false
        for boo in bounds
  	    if boo[0] <= padded_m_num and padded_m_num <= boo[1]
	        good_candidate = true
	    end
	end
	if not good_candidate
	    puts bounds
	    abort("sick of it")
	end
	#puts "====="
	#puts min
	#puts max
	o_accesses += 1

	if bounds.length != 1
	    tmp_r = r
	    #tmp_r = 2*r
	    while true
		ta1 = bounds[0][0]
	        tb2 = bounds[1][1]
	        if tb2-ta1 < 10
	    	    puts "eliminating"
		    f, accesses = eliminate(ta1, tb2, bigB, e, c, n, oracle)
		    puts accesses
		    o_accesses += accesses
		    a = f
		    b = f
		    break
		end

	        #nbounds, accesses = choose_between_two3(start, e, n, c, bigB, oracle, padded_m_num, tmp_r, bounds)
		if experimenting
	            nbounds, accesses = choose_between_two3(start, e, n, c, bigB, oracle, padded_m_num, tmp_r, bounds)
		else
	            nbounds, accesses = choose_between_two1(start, e, n, c, bigB, oracle, padded_m_num, tmp_r, bounds)
		end
		#puts "+++++++++++"
		#puts accesses
		# should be r updated now? at the beginning there is r = 2*r, but r from choose_betwee_two1 is not taken into account
		good_candidate = false
        	for boo in nbounds
  	    	    if boo[0] <= padded_m_num and padded_m_num <= boo[1]
	                good_candidate = true
	     	    end
	  	end
		if not good_candidate
	    	    puts nbounds
	    	    abort("sick of it 1")
		end
		#puts accesses
		o_accesses += accesses

		if nbounds.length == 1
		    ta = nbounds[0][0]
		    tb = nbounds[0][1]
		    if tb-ta < 10
			puts "eliminating"
			f, accesses = eliminate(ta, tb, bigB, e, c, n, oracle)
			puts accesses
			o_accesses += accesses
		 	a = f
			b = f
			break
		    end
		    a = nbounds[0][0]
		    b = nbounds[0][1]
		    break
		end
	    end
	end
	if b-a < 2
            if [a,b].include? padded_m_num 
                puts o_accesses
	        puts "-----------------------------"
                return o_accesses, trimming_accs, best_improvement_a, best_improvement_b
    	    else
		puts "---"
		puts a
		puts b
	    	puts "erhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
	    end
        end
    end
end

all_accesses = 0
j = 0
l = []
trimming_accs = []
best_improvements = []
exp_a = nil
for i in (0..200)
    puts "========================================================"
    puts i
    oracle = RsaOracle.new
    e, n = oracle.get_parameters()
    k = n.to_i.to_s(16).length / 2 # number of bytes of n
    bigB = 256**(k-2)
    c, padded_m = oracle.prepare_some_ciphertext(bigB)
    padded_m_num = padded_m.unpack("H*").join.to_i(16)

    accesses, t_accs, best_improvement_a, best_improvement_b = find_plaintext(oracle, n, e, c, padded_m_num, bigB, true)
    trimming_accs.push(t_accs)
    best_improvements.push([best_improvement_a, best_improvement_b])
    l.push(accesses)
    all_accesses += accesses
    j += 1

    #exp_a, t_accs, best_improvement_a, best_improvement_b = find_plaintext(oracle, n, e, c, padded_m_num, bigB, false)
end
mean = all_accesses/j
sorted_l = l.sort
puts trimming_accs.sort
puts "-----"
puts best_improvements
puts "-----"
puts sorted_l
puts "---------------------"
puts mean
puts sorted_l[j/2]
puts "---++++"
puts exp_a



