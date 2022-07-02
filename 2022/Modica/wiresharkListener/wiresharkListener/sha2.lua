-- https://github.com/JustAPerson/LuaCrypt
-- Le SHA2 Library
--

local bit = require("libbit");

--- Round constants
-- computed as the fractional parts of the cuberoots of the first 64 primes
local k256 = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

--- Preprocess input message
local function preprocess256(input)
	local length = #input;	-- length in bits
	local padding = (-length-9) % 64;
	input = input .. "\128" .. ("\0"):rep(padding) .. "\0\0\0\0" ..
	        bit.int32_str(length*8);
	return input;
end

--- Process an individual block using SHA256
-- Note: Lua arrays start at 1, not 0. 
--       This behavior is respected in loop counters.
--
--@param `input` is the original input message
--@param `t` is the position of the first byte of this block
--@param `H` is the internal hash state
local function digest_block256(input, t, H)
	local s10;	-- Using 1 var for s0,s1 to help LuaJIT register alloc
	local t1, t2;
	local chmaj;	-- May be used in place of s0
	local word;
	local a, b, c, d, e, f, g, h;
	local k = k256;

	local band, bnot, bxor, ror = bit.band, bit.bnot, bit.bxor, bit.ror
	local rshift = bit.rshift;
	local limit = 2^32;

	local W = {};
	local int32 = bit.str_int32;
	local chunk;
	local c1 = 0;	-- #W, #words

	chunk = input:sub(t, t + 63);
	c1 = 0;
	for i = 1, 64, 4 do
		c1 = c1 + 1;
		W[c1] = int32(chunk:sub(i, i+3));
	end

	-- Extend 16 words into 64
	for t = 17, 64 do
		word  = W[t - 2];
		s10   = bxor(ror(word, 17), ror(word, 19), rshift(word, 10));
		word  = W[t - 15];
		chmaj = bxor(ror(word, 7), ror(word, 18), rshift(word, 3));
		W[t]  = s10 + W[t - 7] + chmaj + W[t - 16];
	end

	a, b, c, d = H[1], H[2], H[3], H[4];
	e, f, g, h = H[5], H[6], H[7], H[8];

	for t = 1, 64 do
		s10   = bxor(ror(e, 6), ror(e, 11), ror(e, 25));
		chmaj = bxor(band(e, f), band(bnot(e), g));
		t1    = h + s10 + chmaj + k[t] + W[t];
		s10   = bxor(ror(a, 2), ror(a, 13), ror(a, 22));
		chmaj = bxor(band(a, b), band(a, c), band(b, c));
		t2    = s10 + chmaj;
		h = g;
		g = f;
		f = e;
		e = d  + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	end

	H[1] = (a + H[1]) % limit;
	H[2] = (b + H[2]) % limit;
	H[3] = (c + H[3]) % limit;
	H[4] = (d + H[4]) % limit;
	H[5] = (e + H[5]) % limit;
	H[6] = (f + H[6]) % limit;
	H[7] = (g + H[7]) % limit;
	H[8] = (h + H[8]) % limit;
end

--- Calculate the SHA224 digest of a message
-- Note: sha224() does not use variable names complaint with FIPS 180-2
--@param `input` the message
local function sha224(input)
	local output = "";
	local state;

	input  = preprocess256(input);
	state  = {
		0xc1059ed8,
		0x367cd507,
		0x3070dd17,
		0xf70e5939,
		0xffc00b31, 
		0x68581511, 
		0x64f98fa7, 
		0xbefa4fa4,
	};

	for i = 1, #input, 64 do
		digest_block256(input, i, state);
	end

	for i = 1, 7 do
		output = ("%s%08x"):format(output, state[i]);
	end

	return output;
end

--- Calculate the SHA256 digest of a message
-- Note: sha256() does not use variable names complaint with FIPS 180-2
--@param `input` the message
local function sha256(input)
	local output = "";
	local state;

	input  = preprocess256(input);
	state  = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	};

	for i = 1, #input, 64 do
		digest_block256(input, i, state);
	end

	for i = 1, 8 do
		output = ("%s%08x"):format(output, state[i]);
	end

	return output;
end

return {
	sha224 = sha224;
	sha256 = sha256;
}
