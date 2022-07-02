local sha2 = require 'sha2'

local function _hll_hash (registers) 
	return sha2(registers)
end

--[[Count the number of leading zero's
A leading zero is any 0 digit that comes before 
the first nonzero digit in a number string in positional notation.
For example, James Bond's famous identifier, 007, has two leading zeros]]--
local function _hll_rank (dec_hash,bits) 
 	
 	local rank=0
	
	for i=1,32-bits do
   	    local c = bin_hash:sub(i,i)	 		
   		local bin_hash=toBinString(dec_hash)
   		
   		if c=="1" then break end
  
   		rank=i
   		dec_hash=bit32.rshift(dec_hash,1)
	end

	return rank
end

function hll_reset (hll) 
	return hll_init(hll,19)	
end


function hll_init (hll,bits) 
  
	if bits < 4 or bits > 20 then 
		errno = ERANGE return false
  	end

	hll.bits = bits -- Number of bits of buckets number 
  	-- left shift (n << bits)
  	hll.size=bit32.lshift(1,bits) --Number of buckets 2^bits
  	hll.registers = {} -- Create the bucket register counters 
 
	for i = 1 , hll.size do
		hll.registers[i] = 0
	end
  	--print("bytes", hll.size)

  	return true

end

function hll_destroy (hll) 
  
	if hll.registers then 
    	hll=nil
  	end

end

local function _hll_add_hash (hll,hash) 
		
	if hll.registers then
			
		bin_hash=toBinString(hash)
		dec_hash=toDecBin(bin_hash)
				
		-- Use the first 'hll->bits' bits as bucket index
		-- u_int32_t index = hash >> (32 - hll->bits);
		local index = bit32.rshift(dec_hash, 32-hll.bits)
  		local rank = _hll_rank(dec_hash,hll.bits) --Count the number of leading 0
		
    	if rank > hll.registers[index] then
    	  	hll.registers[index] = rank --Store the largest number of lesding zeros for the bucket  
      	end  
      		  
	end
	
end

function hll_add (hll,item) 
	hash = sha2.sha256(item)
	_hll_add_hash(hll, hash)
end

function hll_count (hll) 

	local estimate = 0	
	local sum = 0
	local alpha_mm = 0	

	if hll.registers then
				
 		if hll.bits==4 then
			alpha_mm = 0.673
		elseif hll.bits==5 then
			alpha_mm = 0.697
		elseif hll.bits==6 then
			alpha_mm = 0.709
		else
			alpha_mm = 0.7213 / (1.0 + 1.079 /hll.size)
		end
		
		alpha_mm =alpha_mm * (hll.size * hll.size)
		
    	for i = 1 , hll.size do
    		sum = sum + (1.0 / bit32.lshift(1,hll.registers[i]))  
		end
		
    	estimate = alpha_mm / sum;

    	if estimate <= (5.0 / 2.0 * hll.size) then
    		local zeros = 0;

    		for i = 1 , hll.size do
				if hll.registers[i] == 0 then
					zeros = zeros + 1
				end			
			end
			
    		if zeros~=0 then
				estimate = hll.size * math.log(hll.size / zeros)
			end
			
    	elseif (estimate > ((1.0 / 30.0) * 4294967296.0)) then 
      		estimate = -4294967296.0 * math.log(1.0 - (estimate / 4294967296.0))
    	end
		
		estimate=math.ceil(estimate)

    	return estimate
	else
    	return(0.)
	end
end


