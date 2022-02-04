
# Realizzato da Giuseppe Graziano e Marco Basile 
#
# progetto Gestione di Reti
# 05/2016

require 'telegram/bot'
require 'sqlite3'
require_relative 'nt_utility.rb'


std_hndlr = trap("INT") do
    STDERR.puts "Terminazione TelegramBot\n\n"
    STDERR.flush
    sleep 2
    exit 0
end

def ls
    _ls = []
    IO.foreach(SITES_FILE) {|sito| _ls << sito.chomp.downcase }
    _ls
end



db = SQLite3::Database.open DB_NAME


sites = []

Telegram::Bot::Client.run(Token) do |bot|
  bot.listen do |message|
    case message.text
    when '/start'
        begin
            db.execute Insert_chat_id, message.chat.id
            begin
                bot.api.send_message(chat_id: message.chat.id, text: "Iscrizione avvenuta con successo :)")
            rescue
            end
            puts message.chat.id
        rescue
        end
    when '/list'
        _ls = ls
        if _ls != []
	        str = _ls.inject(""){|stringa,sito| stringa << (sito.to_s + "\n") }
	        bot.api.send_message(chat_id: message.chat.id, text: str)
	    else
	    	bot.api.send_message(chat_id: message.chat.id, text: "Nessuna keyword salvata.\n")
	    end

    when '/report'
    	str = "REPORT:\n\n"

        _ls = ls
        if _ls != []
	        _ls.each do |keyword|
	            puts keyword
	            byte_sum, duration_sum = (db.execute Report_qry, "%#{keyword.chomp}%").first
	            str << "Keyword: #{keyword}\nBytes: #{byte_sum}\nSeconds: #{duration_sum}\n\n" if !byte_sum.nil? || !duration_sum.nil?
	        end

	    	puts message.chat.id

	        str = "Nothing to report." if str.length < 12
	    else
	    	str = "Nothing to report."
	    end

        begin
        	bot.api.send_message(chat_id: message.chat.id, text: str)
        rescue
        end

    when '/configure'
        begin
            bot.api.send_message(chat_id: message.chat.id, text: "Inserisci la parole chiave da monitorare:")
            bot.listen do |message|
                puts message
                begin
                    sites = []
                    File.open(SITES_FILE,"r").readlines.each {|site| sites << site.chomp.downcase }
                    sites << message.to_s.chomp.downcase
                    File.open(SITES_FILE,"w+") { |file| file.puts sites.uniq ; file.flush }
                rescue Exception => e
                    STDERR.puts e
                    bot.api.send_message(chat_id: message.chat.id, text: "Si e\' verificato un problema, riprova piu\' tardi")
                    break
                else
                	bot.api.send_message(chat_id: message.chat.id, text: "Hai inserito \"#{message}\".")
                	break
                end
            end
        rescue
            bot.api.send_message(chat_id: message.chat.id, text: "Configurazione non andata a buon fine.\nRiprovare.")    
        end
    else
        bot.api.send_message(chat_id: message.chat.id, text: "Comando non riconosciuto.\nRiprova con uno dei comandi disponibili.")

    end
  end
end
