Istruzioni su come utilizzare i tool cdsnoop.py e pagefaultcount.py.
Se sono stati già installati i pacchetti bcc

N.B. è necessario avere una versione del kernel superiore alla 4.1.
Se non si dispone di questa versione vedere configurazione del kernel
a questo link: https://github.com/iovisor/bcc/blob/master/INSTALL.md;
######################################################################
######################################################################

1)Installazione dei pacchetti bcc:

# echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | \
    sudo tee /etc/apt/sources.list.d/iovisor.list
# sudo apt-get update
# sudo apt-get install bcc-tools
######################################################################
######################################################################

2)Scaricare dal seguente link i pacchetti a seconda della disto di 
Linux: 

https://github.com/iovisor/bcc/blob/master/INSTALL.md;
######################################################################
######################################################################

3)Recarsi in una delle cartelle dei tool;
Per l'utilizzo di entrambi i tool è necessario essere root;
Cambiare i diritti di esecuzione del file .py:
		#chmod +x nome.py
Oppure eseguire lo script con:
		#python nome.py
######################################################################
######################################################################

4.1)Se si sta eseguendo cdsnoop aprire altre bash ed eseguire comandi
cd per testare il programma
4.2)Se si sta eseguendo pagefaultcount per stamapare
l'output aspettare 100secondi oppure interrompere il programma con Ctrl+C
