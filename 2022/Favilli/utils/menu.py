import sys

def menu():
    print("Select the attack tipology to analyze analysis (enter quit to exit)")
    print("\n\t1) Newtwork attacks\n\t2) Recon attacks\n\t3) All methods")

    choice = []

    upperbound = 3
    lowerbound = 1

    user_input = checkInput(input(""), upperbound, lowerbound)
    while(user_input < lowerbound or user_input > upperbound):
        user_input = checkInput(input(""), upperbound, lowerbound)
       
    if(user_input == 1):
        choice.append(1)
        return networkAttacksMenu(choice)
    elif(user_input == 2):
        choice.append(2)
        return reconMenu(choice)
    elif(user_input == 3):
        choice.append(3)
        return choice
    
def checkInput(input, upperBound, lowerBound):

    if(input == "quit"):
        sys.exit(0)
    try:
        val = int(input)
    except ValueError:
        print("Enter an integer")
        return -1
    
    if(val < upperBound + 1 and val > lowerBound - 1):
        return val
    else:
        print(f"Enter an integer between {lowerBound} and {upperBound}")
        return -2

############### NETWORK ATTACKS #########################
        
def networkAttacksMenu(choice):
    print("Select the typology of attack you want to analyze")
    print("\n\t1) Spoofing\n\t2) DoS/DDoS\n\t3) Vlan\n\t4) All network attacks\n")

    upperbound = 4
    lowerbound = 1

    user_input = checkInput(input(""), upperbound, lowerbound)
    while(user_input < lowerbound or user_input > upperbound):
        user_input = checkInput(input(""), upperbound, lowerbound)
    
    return switchNetworkAttack(user_input, choice)


def spoofingMenu(choice):
    print("Enter the spoofing method you want to analyze")
    print("\n\t1) Arp spoofing\n")

    upperbound = 1
    lowerbound = 1

    user_input = checkInput(input(""), upperbound, lowerbound)

    while(user_input < lowerbound or user_input > upperbound):
        user_input = checkInput(input(""), 1, 1)
    if(user_input == 1):
        choice.append(1)
        return choice

def ddosMenu(choice):
    print("Enter the dos/ddos attacks you want to analyze")
    print("\n\t1) packet loss\n\t2) ping of death\n\t3) icmp flood\n\t4) syn flood\n\t5) dns request flood\n\t6) All ddos attacks\n")

    upperbound = 6
    lowerbound = 1

    user_input = checkInput(input(""), upperbound, lowerbound)

    while(user_input < lowerbound or user_input > upperbound):
        user_input = checkInput(input(""), upperbound, lowerbound)

    if(user_input == 1):
        choice.append(1)
        return choice
    elif(user_input == 2):
        choice.append(2)
        return choice
    elif(user_input == 3):
        choice.append(3)
        return choice
    elif(user_input == 4):
        choice.append(4)
        return choice
    elif(user_input == 5):
        choice.append(5)
        return choice
    elif(user_input == 6):
        choice.append(6)
        return choice

def vlanMenu(choice):
    print("Enter the vlan attack you want to analyze")
    print("\n\t1) vlan hopping\n")
    
    upperbound = 1
    lowerbound = 1

    user_input = checkInput(input(""), upperbound, lowerbound)
    while(user_input < lowerbound or user_input > upperbound):
        user_input = checkInput(input(""), upperbound, lowerbound)
    if(user_input == 1):
        choice.append(1)
        return choice

def switchNetworkAttack(case, choice):
    if(case == 1):
        choice.append(1)
        return spoofingMenu(choice)
    elif(case == 2):
        choice.append(2)
        return ddosMenu(choice)
    elif(case == 3):
        choice.append(3)
        return vlanMenu(choice)
    elif(case == 4):
        #all networkAttacks
        choice.append(4)
        return choice
    else:
        print("An unkown error has occurred")
        sys.exit(-1)


############# RECON ##################

def reconMenu(choice):
    print("Select the typology of attack you want to analyze")
    print("\n\t1) Host Discovery\n")

    upperbound = 1
    lowerbound = 1
    
    user_input = checkInput(input(""), upperbound, lowerbound)
    while(user_input < lowerbound or user_input > upperbound):
        user_input = checkInput(input(""), upperbound, lowerbound)

    if(user_input == 1):
        choice.append(1)
        return hostDiscoveryMenu(choice)
    

def hostDiscoveryMenu(choice):
    print("Enter the host discovery scan you want to analyze")
    print("\n\t1) arp\n\t2) ip protocol\n\t3) icmp ping\n\t4) tcp syn\n\t5) tcp ack\n\t6) udp\n\t7) all scans\n")

    upperbound = 7
    lowerbound = 1

    user_input = checkInput(input(""), upperbound, lowerbound)
    while(user_input < lowerbound or user_input > upperbound):
        user_input = checkInput(input(""), upperbound, lowerbound)

    if(user_input == 1):
        choice.append(1)
        return choice
    elif(user_input == 2):
        choice.append(2)
        return choice
    elif(user_input == 3):
        choice.append(3)
        return choice
    elif(user_input == 4):
        choice.append(4)
        return choice
    elif(user_input == 5):
        choice.append(5)
        return choice
    elif(user_input == 6):
        choice.append(6)
        return choice
    elif(user_input == 7):
        choice.append(7)
        return choice