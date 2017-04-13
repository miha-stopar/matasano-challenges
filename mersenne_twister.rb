class MersenneTwister  
    attr_accessor :mt

    def initialize(seed)
	@mt = Array.new
	@index = 0
	@lowest32 = 2 ** 32 - 1
	@bit32 = 2 ** 31
	@last31 = 2 ** 31 - 1
	initialize_generator(seed)
    end

    def initialize_generator(seed)
        @mt[0] = seed
        for i in (1..623)
    	    t = (1812433253 * @mt[i-1]) ^ ((@mt[i-1] >> 30) + i)
            @mt.push(t & @lowest32)
    	end
    end

    def extract_number()
        if @index == 0
    	    generate_numbers()
        end
        y = @mt[@index]
        y ^= y >> 11
        y ^= (y << 7) & 2636928640
        y ^= (y << 15) & 4022730752
        y ^= y >> 18
        @index = (@index + 1) % 624
        return y
    end

    def generate_numbers()
        for i in (0..623)
    	    y = (@mt[i] & @bit32) + (@mt[(i + 1) % 624] & @last31)
            @mt[i] = @mt[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0
                @mt[i] ^= 2567483615
	    end
        end
    end
end
