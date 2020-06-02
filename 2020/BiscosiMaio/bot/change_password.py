#!/usr/bin/python3

#
# Import
import sys
import json
from hashlib import *
from package_login.login import logClass


def chang_p():
    """ Change the password of the bot.
    """
    # Check if received the right number of arguments
    if len(sys.argv) != 3:
        print('Usage: ./change_password.py <old_password> <new_password>')

    else:
        args = list(sys.argv)

        # Encrypt password
        hashword = sha256(args[1].rstrip().encode()).hexdigest()
        with open('package_login/password.json', 'r') as f:
            data = json.load(f)

        # Check if argument corresponds to password encrypted locate
        # package_login/password.json
        if hashword == data['password']:

            # Encrypt new password
            new_hashword = sha256(args[2].rstrip().encode()).hexdigest()
            data['password'] = new_hashword

            # Save the new encrypted password
            with open('package_login/password.json', 'w') as file:
                json.dump(data,file)

            # Change value of ClassLogin instance
            logClass.set_password(new_hashword)
        else:
            print('Uncorrect old password, try again')

chang_p()