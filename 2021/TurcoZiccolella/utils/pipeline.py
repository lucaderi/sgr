import threading
import datetime
import os

class Pipeline:
    def __init__(self):
        self.message = None
        self.consumer_lock = threading.Lock()
        self.consumer_condition = threading.Condition(self.consumer_lock)

    def get_message(self, name):
        self.consumer_lock.acquire()

        while self.message is None:
            self.consumer_condition.wait()
        message = self.message
        self.message = None
        self.consumer_condition.notify()

        self.consumer_lock.release()
        return message

    def set_message(self, message, name):
        self.consumer_lock.acquire()
        p = '%Y-%m-%d--%H:%M:%S'
        if self.message is not None:
            print("Il consumatore ha perso una cattura")
            # controllo
            os.remove(datetime.datetime.fromtimestamp(self.message).strftime(p) + '.pcap')  # cancella la cattura persa
        self.message = message
        print("cattura terminata e invio!")
        self.consumer_condition.notify()

        self.consumer_lock.release()
