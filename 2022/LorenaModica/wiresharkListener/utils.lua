---checks if a string represents an ip address
-- @return true or false
function check_ipv4(ipv4_address)
	
	if type(ipv4_address) ~= "string" then return false end

  	-- check for format 1.11.111.111 for ipv4
  	local chunks = {ipv4_address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  	
	if #chunks == 4 then
    	for _,v in pairs(chunks) do
      		if tonumber(v) > 255 then return false end
    	end
		return true
  	end

end

--code from https://stackoverflow.com/questions/17650169/binary-code-to-string
function toBinString(s)
	bytes = {string.byte(s,i,string.len(s))}
  	binary = ""

  	for i,number in ipairs(bytes) do
    	c = 0

    	while(number>0) do
      		binary = (number%2)..binary
      		number = number - (number%2)
      		number = number/2
      		c = c+1
    	end

    	while(c<8) do
      		binary = "0"..binary
      		c = c+1
    	end
	
	end

  return binary

end

function toDecBin(bin)

	bin = string.reverse(bin)
	local sum = 0

	for i = 1, string.len(bin) do
  		num = string.sub(bin, i,i) == "1" and 1 or 0
		sum = sum + num * math.pow(2, i-1)
	end
	
	return sum

end




