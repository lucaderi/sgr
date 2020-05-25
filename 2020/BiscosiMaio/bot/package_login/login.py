
#
# Import
import json
from hashlib import sha256


class ClassLogin:
    """ Class used to manage login phases.

    """
    password = ""

    def __init__(self):
        with open('./package_login/password.json') as f:
            data = json.load(f)

        self.password = data['password']

    def set_password(self, passord):
        """ Change the password.

        :param passord: new password.
        """
        self.password = passord

    def get_password(self):
        """ Take the password

        :return: password value.
        """
        return self.password

    def method_loginid(self, chat_id, password):
        """ Manage sign in of chat_id.

        :param chat_id: chat id that want to sign in.
        :param password: password sent by chat id.
        :return: True if login completed seccessfully, False else.
        """

        with open('./package_login/logged.json', 'r') as f:
            data = json.load(f)

        cpass = sha256(password.rstrip().encode()).hexdigest()
        id_c = sha256(str(chat_id).rstrip().encode()).hexdigest()
        if cpass == self.password:

            # password ok
            ids = data
            find_it = False
            find_user=""

            for x in ids:
                if x['chat_id'] == id_c:
                    find_it = True
                    find_user = x
                    break

            if find_it:
                # find user user in json.
                if find_user['password'] != cpass:

                    # this id was logged in with old password
                    # so update the password.
                    find_user['password'] = cpass
                    find_user['is_logged'] = True

                else:
                    #
                    # id was already logged in.
                    find_user['is_logged'] = True

                # update json object.
                for x in data:
                    if x['chat_id'] == id_c:
                        x['is_logged'] = True
                        x['password'] = cpass

            else:
                # the id wasn't logged in, but it cans, because it
                # inserted right password.
                find_user = {
                    'chat_id': id_c,
                    'is_logged': True,
                    'password': cpass
                }
                data.append(find_user)

            # update json file
            with open('./package_login/logged.json', 'w') as json_file:
                json.dump(data, json_file)
            return True
        else:
            return False

    def method_isloggedid(self, chat_id):
        """ Check if id is logged in.

        :param chat_id: chat id that want to execute some commands
        :return 0: if login ok with updated password;
        :return 1: if login ok with old password;
        :return 2: login not ok.
        """
        with open('./package_login/logged.json') as f:
            data = json.load(f)

        find_it = False
        find_user = ""
        id_c = sha256(str(chat_id).rstrip().encode()).hexdigest()
        for x in data:
            if x['chat_id'] == id_c:
                find_it = True
                find_user = x
                break

        if find_it:
            if find_user['password'] != self.password:
                return 1
            else:
                return 0
        else:
            return 2


logClass = ClassLogin()
