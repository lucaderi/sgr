import threading
import datetime
import os

class Pipeline:
    def __init__(self):

        self.ts = None
        self.f_name = None

        self.consumer_lock = threading.Lock()
        self.consumer_condition = threading.Condition(self.consumer_lock)

    def get_message(self):
        self.consumer_lock.acquire()

        while self.ts is None:
            self.consumer_condition.wait()

        ts = self.ts
        f_name = self.f_name

        self.ts = None
        self.f_name = None

        self.consumer_condition.notify()

        self.consumer_lock.release()
        return ts, f_name

    def set_message(self, timestamp , f_name):
        self.consumer_lock.acquire()

        if self.ts is not None:
            #there is a limit of one saved pcap, if the consumer missed a pcap it's deleted and lost forever
            print("Il consumatore ha perso una cattura")
            os.remove(self.f_name)

        self.ts = timestamp
        self.f_name = f_name

        print("cattura terminata e invio!")

        self.consumer_condition.notify()

        self.consumer_lock.release()
