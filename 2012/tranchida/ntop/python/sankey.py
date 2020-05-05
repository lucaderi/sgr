#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
	file		 sankey.py
	author		 Tranchida Giulio, No Matricola 241732\n
				 Si dichiara che il contenuto di questo file e',
 				 in ogni sua parte, opera originale dell'autore.\n\n

	version 1.0
	copyright (C) 2011 Tranchida Giulio under GNU Public License v2.
  
	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
	MA  02110-1301, USA.
'''
import json, cgi
import sys, time, socket
from operator import itemgetter, attrgetter
# ntop interface
import interface

class Flow:
	def __init__(self):
		self.time = time.time();
		self.archi = {}							# Ricerca per coppie di nodi
		self.form = cgi.FieldStorage()
		self.host = {}							# Ricerca per singolo host (ordinamento per dimensione del flusso)
		self.l4 = set()							# Ricerca per layer 4
		self.l7 = set()							# Ricerca per layer 7
		self.l4selected = self.form.getlist('layer4[]')			# Protocolli layer4 selezionati dall'utente
		self.l7selected = self.form.getlist('layer7[]')			# Protocolli layer7 selezionati dall'utente
		self.maxhost = int(self.form.getvalue('maxhost', default=16))	# Massimo numero di host da vis...
		self.source = self.form.getvalue('source')			#
		self.target = self.form.getvalue('target')			#
		self.hostselected = self.form.getvalue('hostselected[]')

		# Performance tweaks
		archi = self.archi
		sourceip = self.source
		targetip = self.target
		host = self.host
		layer4_add = self.l4.add
		layer7_add = self.l7.add
		hostselected = self.hostselected
		l4selected = self.l4selected
		l7selected = self.l7selected

		if sourceip and targetip:
			flows = interface.dumpHostRawFlows(sourceip)
		else:
			flows = interface.dumpHostRawFlows(hostselected)

		if not flows:
#			print >> sys.stderr, "flows is null"
			return

		for line in flows:			
			dati = line.strip('\n').split("|")
			source = dati[0]
			target = dati[1]
			outBytes = int(dati[2])
			inBytes = int(dati[3])
			protocol4 = dati[4]
			protocol7 = dati[5]

			# Creo la lista di tutti gli host
			try:
				host[source] += outBytes+inBytes
			except KeyError:
				host[source] = outBytes+inBytes

			try:
				host[target] += outBytes+inBytes
			except KeyError:
				host[target] = outBytes+inBytes

			# Un ulteriore filtro su i dati d'ingresso puo' essere effettuato
			# se si e' definita una sorgente/destinazione di un flusso
			if sourceip and targetip:
				if ((not (sourceip == source and targetip == target)) and
					 (not (sourceip == target and targetip == source))):
					continue

			# Una volta definito il sottoinsieme di protocolli layer 4 / layer 5 
			# che si vuole visualizzare si scartera' in fase di creazione della
			# struttura dati i protocolli che non ci interessa valutare.

			layer4_add(protocol4)
			if l4selected and protocol4 not in l4selected: continue

			layer7_add(protocol7)
			if l7selected and protocol7 not in l7selected: continue

			# Seleziono i flussi che appartengono solo ad un singolo host
			if hostselected and hostselected != source and hostselected != target:
				continue

			# Struttura dati per coppia di nodi
			# Evitiamo di costruire un grafo con cicli (il grafico non li supporta)
			if source > target:
				try:
					data = archi[(source, target)]
					data[0] += outBytes+inBytes
					data[1] += outBytes
					data[2] += inBytes				
					try:
						proto4 = data[3][protocol4]
						proto4[0] += outBytes+inBytes
						try:
							proto5 = proto4[1][protocol7];
							proto5[0] += outBytes+inBytes
							proto5[1] += outBytes
							proto5[2] += inBytes

						except KeyError:
							proto4[1][protocol7] = [outBytes+inBytes, outBytes, inBytes]

					except KeyError:
						data[3][protocol4] = [outBytes+inBytes, 
								{protocol7:[outBytes+inBytes, outBytes, inBytes]}]

				except KeyError:
					archi[(source, target)] = [outBytes+inBytes, outBytes, inBytes, 
						{protocol4:[outBytes+inBytes,
							 {protocol7:[outBytes+inBytes, outBytes, inBytes]}]}]

			elif source < target:
				try:
					data = archi[(target, source)]
					data[0] += outBytes+inBytes
					data[1] += inBytes
					data[2] += outBytes
					try:
						proto4 = data[3][protocol4]
						proto4[0] += outBytes+inBytes
						try:
							proto5 = proto4[1][protocol7];
							proto5[0] += outBytes+inBytes
							proto5[1] += inBytes
							proto5[2] += outBytes

						except KeyError:
							proto4[1][protocol7] = [outBytes+inBytes, inBytes, outBytes]

					except KeyError:
						data[3][protocol4] = [outBytes+inBytes,
							{protocol7:[outBytes+inBytes, inBytes, outBytes]}]

				except KeyError:
					archi[(target, source)] = [outBytes+inBytes, inBytes, outBytes,
						{protocol4:[outBytes+inBytes,
							{protocol7:[outBytes+inBytes, inBytes, outBytes]}]}]

			else:		# Connessioni loopback (non supportate dal grafico)
				pass

		# --- chiusura ciclo for ---------------------------------------------------

	# ----- fine costrutore di classe -------------------------------------------------------

	def json(self, nodes, links, metadata):
		metadata['time'] = "%.3f sec" % (time.time() - self.time)
		result = {'nodes':[{'name':el} for el in nodes], 'links':links, 'metadata':metadata}
		return json.dumps(result, sort_keys=False, indent=4)

	# Host to Host graph (First view)
	def getjsondata(self):

		if self.form.has_key('source') and self.form.has_key('target'):
			return self.drawzoom()

		nodes = []					# Lista di tutti i nodi senza duplicati
		links = []					# Lista di tutti i link
		metadata = {}				# metainformazioni

		# Performance tweaks
		l4 = self.l4
		l7 = self.l7
		l4selected = self.l4selected
		l7selected = self.l7selected
		nodes_index = nodes.index
		nodes_append = nodes.append
		links_append = links.append

		archiordinati = self.archi.items()
		archiordinati.sort(key=itemgetter(1), reverse=True)	# worst case O(n(log n))
		l4 = sorted(l4)
		l7 = sorted(l7)

		hostordinati = self.host.items()
		hostordinati.sort(key=itemgetter(1), reverse=True)

		if not l4selected: l4selected = l4
		if not l7selected: l7selected = l7

		# Creo i nodi (host)
		for ind in archiordinati[0:self.maxhost]:
			newind = list(ind[0])
			[nodes_append(index) for index in newind if index not in nodes]

# Q. Quali dell due espressioni e' preferibile usare ??
#			ovvero quante volte viane valutata l'espressione list(ind[0]) ??
#		[nodes_append(index) for ind in archiordinati[0:self.maxhost] for index in list(ind[0]) if index not in nodes]

		# Creo gli archi
		for ind in archiordinati[0:self.maxhost]:
			newindex = list(ind[0])
			if (ind[1][1]>0):
				links_append({
					'source':nodes_index(newindex[0]),'target':nodes_index(newindex[1]),
					'value':(ind[1][1]),'direction':1})
			if (ind[1][2]>0):
				links_append({
					'source':nodes_index(newindex[0]),'target':nodes_index(newindex[1]),
					'value':(ind[1][2]),'direction':0})

		metadata = {'zoom':0, 'unit':'bytes',
					'layer4':[el for el in l4],
					'layer4selected':[el for el in l4selected],
					'layer7':[el for el in l7],
					'layer7selected':[el for el in l7selected],
					'hostlist':[el[0] for el in hostordinati[0:self.maxhost]],
					'hostselected':self.hostselected}

		return self.json(nodes, links, metadata)

	# Host to Layer 4 to Host (Second view)
	def drawzoom(self):
		nodes = []					# Lista di tutti i nodi senza duplicati
		links = []					# Lista di tutti i link
		metadata = {}				# metainformazioni
		doall = False

		# Performance tweaks
		archi = self.archi
		source = self.source
		target = self.target
		l7selected = self.l7selected
		nodes_index = nodes.index
		nodes_append = nodes.append
		links_append = links.append
		l7selected_append = self.l7selected.append

		# Recupero i nodi del livello 4
		layer4ordinato = archi[(source, target)][3].items()
		layer4ordinato.sort(key=itemgetter(1), reverse=True)

		# Inserisco i nodi genitori (gli host)
		nodes_append(source)
		nodes_append(target)
		# aggiungo la lista dei nodi (il layer 4)
		[nodes_append(index[0]) for index in layer4ordinato]

		for index in layer4ordinato:
			protocol7 = archi[(source, target)][3][index[0]][1]
			layer7ordinato = protocol7.items()
			layer7ordinato.sort(key=itemgetter(1), reverse=True)

			# Se nessun layer e' selezionato li aggiungo tutti
			if doall:
				[l7selected_append(index2[0]) for index2 in layer7ordinato]
			if not l7selected:
				[l7selected_append(index2[0]) for index2 in layer7ordinato]
				doall = True

			for index2 in layer7ordinato[0:self.maxhost]:
				if index2[0] not in l7selected: continue

				# Recupero i byte in uscita
				if (index2[1][1]>0):
					links_append({
						'source':nodes_index(source), 'target':nodes_index(index[0]),
						'layer4':index[0], 'layer7':index2[0],
						'value':(index2[1][1]), 'direction':1})
					links_append({
							'source':nodes_index(index[0]), 'target':nodes_index(target),
							'layer4':index[0], 'layer7':index2[0],
							'value':(index2[1][1]), 'direction':1})

				# Recupero i byte in ingresso
				if (index2[1][2]>0):
					links_append({
						'source':nodes_index(source), 'target':nodes_index(index[0]),
						'layer4':index[0], 'layer7':index2[0],
						'value':(index2[1][2]), 'direction':0})
					links_append({
						'source':nodes_index(index[0]), 'target':nodes_index(target),
						'layer4':index[0], 'layer7':index2[0],
						'value':(index2[1][2]), 'direction':0})

		metadata = {'zoom':1, 'unit':'bytes',
					'source':source,
					'target':target,
					'layer7':[el for el in self.l7],
					'layer7selected':[el for el in l7selected]}

		return self.json(nodes, links, metadata)

#_______________________________________________________________________________________________________

flows = Flow()

print "HTTP/1.1 200 OK"
print "Content-type: application/json; charset=UTF-8"
print										# End of headers
print flows.getjsondata()

'''_____________________________________________________________________________________________________

# Esempio
# nprobe -P /tmp/ -i wlan0 -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %OUT_BYTES %IN_BYTES %PROTOCOL %L7_PROTO_NAME"
# IPV4_SRC_ADDR|IPV4_DST_ADDR|OUT_BYTES|IN_BYTES|PROTOCOL|L7_PROTO_NAME
# 172.16.0.8|176.31.106.125|4775960|86788|16|6|Unknown
_______________________________________________________________________________________________________ '''

