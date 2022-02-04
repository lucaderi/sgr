
# Realizzato da Giuseppe Graziano e Marco Basile 
#
# progetto Gestione di Reti
# 05/2016

require 'open3'
require 'net/http'
require 'uri'
require 'json'
require 'sqlite3'
require 'telegram/bot'
require_relative 'nt_utility.rb'


pid = -1 #pid del processo redis-server
go = true #bool per l'esecuzione dei thread

MAC = `ifconfig en0 | grep ether`.split(/\s+/).last

if ARGV.length > 0
	case ARGV.first
	when "-h","--help"
		STDERR.puts "Usage 'ruby net_analytics <interface>'\nor without param the interface will be 'en0' for MacOSX.\nTo show all available interface, type 'ntopng -h'.\n\n"
		exit 1
	end
end



interface = ARGV[0] || "en0"

unless Dir.exist?("DATA")
	Dir.mkdir("DATA")
end

system("rm DATA/* &> /dev/null")

already_existed = true && File.readable?(DB_NAME)

db = SQLite3::Database.open DB_NAME


(db.execute Create_qry; db.execute Create_qry_2) unless already_existed

db.execute Delete_qry

########################################

std_hndlr = trap("INT") do
	go = false
end

#siti da monitorare
sites = []

#siti già trovati
notified = []

# carichiamo dal file di testo i chat_id noti
chat_ids = []
db.execute(Get_chat_id).each do |id|
	chat_ids << id
end


############
siti_ultima_modifica = nil

if File.readable?(SITES_FILE)
	File.open(SITES_FILE, "r").readlines.each do |site|
		sites << site.chomp
	end
else
	File.open(SITES_FILE,"w+").close
end

siti_ultima_modifica = File.mtime(SITES_FILE).to_i


########################################

Open3.popen2e("redis-server") do |r_in,r_out,r_th|
	pid = r_th.pid

	n_in,n_out,n_th = Open3.popen2e("ntopng -i #{interface}")

	sleep 1 #diamo il tempo ad ntopng di avviarsi

	#avviamo testbot
	_n_in,_n_out,_n_th = Open3.popen2e("ruby telegrambot.rb")

	### produttore ###
	produttore = Thread.new do

		while go

			begin
				str = `curl --cookie "user=admin; password=admin" 'http://localhost:3000/lua/get_flows_data.lua?ifname=en0&perPage=30000'`
				json = JSON.parse(str)
			rescue
				#caso in cui viene interrotto il download dei json
			end

			File.open("DATA/#{Time.new().to_i}.json", "w") do |file|
				file.puts json.to_json
				file.flush
			end

			sleep 1 if go

		end
	end

	### fine produttore ###
	
	### consumatore ###
	consumatore = Thread.new do
		
		while go do
			ls = Dir.entries("DATA").select { |file| file =~ /json/ }.sort
			
			ls.each do |file|
				tm = File.mtime(SITES_FILE).to_i
				if tm != siti_ultima_modifica
					sites = []

					File.open(SITES_FILE,"r").readlines.each {|site| sites << site.chomp }
					siti_ultima_modifica = tm
				end

				begin
					_json = JSON.parse(File.open("DATA/#{file}","r").read)
				
				rescue JSON::JSONError => e
					STDERR.puts "Errore JSON #{file}"
					STDERR.flush
				rescue #in questo caso sara' errore dovuto alla open del file
					STDERR.puts "Errore apertura #{file}"
					STDERR.flush
				else
					data = _json["data"] # array di dizionari
					

					#rimuovo da notified se il sito non è più presente
					notified.each { |site|  
						if !data.any? { |el| el["column_info"][site] || el["column_server"][site] } then
							puts "rimuovo #{site}"
							notified.delete(site)
						end
					}
					
					data.each do |el|
						ar = el["key"],el["column_info"],el["column_server"].gsub(%r{</?[^>]+?>},''),el["column_duration"].ntduration,el["column_bytes"].ntbytes
						_key, _info, _server, _duration, _byte = ar
						begin 
							db.execute Insert_qry, ar
						rescue
							# qui e' stato 'inserito' un item gia' presente, va bene cosi'
						else
							# inserimento nel db avvenuto, procediamo al processing

							sites.each do |site|  

								if _info[site] && !notified.any? { |s| s[site] } then

									chat_ids = db.execute Get_chat_id #aggioriamo le chat_ids
									notified.push(site)
									

									STDOUT.puts "Trovata keyword #{site}!\nUser: #{ENV['USER']}\nMAC: #{MAC}"
									STDOUT.flush

									Telegram::Bot::Client.run(Token) do |bot|
										STDOUT.puts chat_ids
										STDOUT.flush
										chat_ids.each do |chat_id|
											begin
												bot.api.send_message(chat_id: chat_id.first, text: "Trovata keyword #{site}!\nUser: #{ENV['USER']}\nMAC: #{MAC}\nsito: #{_info}\nindirizzo: #{_server}")
											rescue
												db.execute Remove_chat_id, chat_id.first
												STDERR.puts "CANCELLATO ISCRITTO #{chat_id.first}"
												STDERR.flush
											end
										end
									end
								end
							end
						end
					end
				end

				#eliminiamo il file appena processato
				File.delete("DATA/#{file}")

			end

			sleep 2 if go

		end
	end

	### fine consumatore ###

	produttore.join
	consumatore.join

	STDERR.puts "\nnet_analytics termina con successo.\n\n"
	STDERR.flush
	
end


exit 0

