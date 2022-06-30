--https://github.com/JustAPerson/LuaCrypt

local output = {};

--
-- Binary logic operators
--
do
	local bitop_present = pcall(require, "bit");
	local lua52 = _VERSION == "Lua 5.2";
	local native = bitop_present or lua52;

	if native then
		local lib = lua52 and bit32 or require("bit");
		local search = "band bnot bor bxor lshift rshift "

		for word in search:gmatch("(.-)%s") do
			output[word] = lib[word];
		end

		if lua52 then
			output.rol = lib.lrotate;
			output.ror = lib.rrotate;
		elseif bitop_present then
			output.rol = lib.rol;
			output.ror = lib.ror;
		end
	else
		-- TODO: implement bit ops in Lua
	end
end

--
-- Binary conversion helper functions
-- Note: Big endian 
--
do
	-- Convert a raw 32 bit integer to a 4 byte string.
	function output.int32_str(input)
		local output;
		local char = string.char;

		output = char(input / 256^3);
		input  = input % 256^3;
		output = output .. char(input / 256^2);
		input  = input % 256^2;
		output = output .. char(input / 256);
		input  = input % 256;
		output = output .. char(input);

		return output;
	end

	--	Convert a 4 byte string to a raw integer.
	function output.str_int32(input)
		local output;
		local a, b, c, d = input:byte(1, 4, 4);

		output = a * 256^3;
		output = output + b * 256^2;
		output = output + c * 256;
		output = output + d;

		return output;
	end

	-- Todo: 64 bit functions
	-- Will consist of a table of two integers:
	-- {
	--		high_word,
	--		low_word,
	-- }

	--[[
	function output.int64_str(input)
	end
	function output.str_int64(input)
	end
	--]]
end

return output;
