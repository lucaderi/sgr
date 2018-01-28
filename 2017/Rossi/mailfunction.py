#! /usr/bin/env python

# I indicate with "###-----" the lines before those that you have to modify

import smtplib
import sys

def sendAlarm(str1,str2):

###-----mail address used to deliver
 fromaddr = 'sender@exampleaddr.com'

###-----password of the mail address
 p = 'password' 

###-----mail address of the admin
 toaddrs  = 'receiver@exampleaddr.com'
  
###-----you server SMTP (default value is to gmail smtp)
 serverName = 'smtp.gmail.com:587'


 msg = """From: From PingChecker 
To: To Admin
MIME-Version: 1.0
Content-type: text/html
Subject: Unreachable host

Host <b>"""+str1+"""</b> seems not reachable by """+str2+" polling cycles"
 try:  
 	server = smtplib.SMTP(serverName)
 except: 
 	print("unable to connect to SMTP, email not delivered")
 	print("please check the serverName")
 	print("and check the raised exception")
 	print("------exception------")
 	raise
 server.starttls()
 try:
 	server.login(fromaddr,p)
 except:
	print("Server OK, but")
	print("login error, email not delivered")
	print("please check you username and password")
	print("and check the raised exception")
	print("------exception------")
	raise
 try:
        server.sendmail(fromaddr, toaddrs, msg)
 except:
 	print("Server and login OK, but")
 	print("unable to deliver mail")
	print("check the raised exception")
	print("------exception------")
	raise
 
 print("email delivered")
 server.quit()
