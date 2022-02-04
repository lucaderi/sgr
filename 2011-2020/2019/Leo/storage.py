
class Storage:
	"""classe usata per la memorizzazione delle informazioni necessarie al calcolo delle statistiche"""
	def __init__(self):
		self.dic = {}
		self.byte = 0

	
	#@brief: aggiorna le occorrenze associate a name nel dizionario
	def updateStorage(self,name):
		if name in self.dic:
			self.dic[name] += 1 #incremento contatore associato
		else:
			self.dic.update({name:1}) #inserisco il nuovo nome nel dizionario

	#@brief: aggiorna il volume del traffico dns
	def updateV(self,b):
		self.byte += b
		return

	#@brief: ritorna il numero di byte accumulati
	def getV(self):
		
		return self.byte
	
	#brief: restitusice gli elementi contenuti nel dizionario
	def getList(self):

		return self.dic.items() 