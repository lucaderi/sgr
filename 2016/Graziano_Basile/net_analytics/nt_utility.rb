
# Realizzato da Giuseppe Graziano e Marco Basile 
#
# progetto Gestione di Reti
# 05/2016

###########################################

token = nil

if File.readable?("token.txt")
	IO.foreach("token.txt") do |line|
		token = line
	end
end

Token = token

DB_NAME = "big_bro.db" #file database
SITES_FILE = "sites.txt" #file dei siti da monitorare


Delete_qry = <<EOF
DELETE FROM Big_Bro;
EOF

Create_qry = <<EOF
CREATE TABLE Big_Bro ( key integer PRIMARY KEY, info char(100), server char(100), duration integer, byte integer);
EOF

Create_qry_2 = "CREATE TABLE Chat_id ( id char(20) PRIMARY KEY );"

Insert_qry = <<-EOF
INSERT INTO Big_Bro VALUES (?, ?, ?, ?, ?);
EOF

Get_chat_id = <<-EOF
SELECT * FROM Chat_id;
EOF

Insert_chat_id = <<-EOF
INSERT INTO Chat_id VALUES (?);
EOF

Remove_chat_id = <<-EOF
DELETE FROM Chat_id WHERE id = ? ;
EOF

Report_qry = <<-EOF
SELECT SUM(byte) AS Bbyte ,SUM(duration) AS Dduration FROM Big_Bro WHERE info LIKE ? ORDER BY Bbyte DESC, Dduration DESC;
EOF

###########################################

class String
	def ntbytes
		str = self.split(/\s+/)
		doubl = str.first.to_f
		fattore = 1.0

		case str.last
		when /k/i
			fattore = 1_024.0
		when /m/i
			fattore = 1_024.0 * 1_024.0
		when /g/i
			fattore = 1_024.0 * 1_024.0 * 1_024.0
		else
			#fattore e' gia 1.0 per byte
		end

		(doubl * fattore).to_i
	end

	def ntduration
		str = self.split(/\s?,\s?/).map {|p| p.chomp }
		
		duration = 0

		str.each do |p|
			el = p.split /\s+/
			d = el.first.to_i

			case el.last
			when /ec/i
				duration += d
			when /in/i
				duration += d * 60
			when /our/i
				duration += d * 60 * 60
			when /ay/i
				duration += d * 60 * 60 * 24
			else

			end
		end

		duration
	end

end
