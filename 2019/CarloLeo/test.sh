

if [[ $# != 2 ]]; then
	echo "Passare nome interfaccia allo script"
	echo "bash test.sh -i [interfaccia]"
	exit 1
fi
echo "Il test termina all'esaurimento del tempo di cattura: 1.5 minuti"

sudo time python3.6 dns_sniffer.py -i $2 -m 1.5 -n 1000 & #1000 per far stampare la clasifica completa


pid=$!

sleep 20 #aspetto inserimento della password per il comando sudo

echo "Inizio a generare traffico DNS"
while read -r line; #risolvo i nommi contenuti nel file lista.txt per generare traffico DNS
do
  #echo "$line"
  host $line &> dev/null
done < lista.txt

echo "ASPETTO LA TERMINAZIONE DEL dns_sniffer"
printf "\n"

wait $pid #aspetto la terminazione del processo

printf "\n"
printf "Test terminato\n"
