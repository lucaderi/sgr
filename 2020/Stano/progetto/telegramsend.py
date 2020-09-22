import telegram


def telegramsend(msg, chat_id, token):
    bot = telegram.Bot(token=token)
    bot.sendMessage(chat_id=chat_id, text=msg)


class TelegramSender:
    def __init__(self, token, chat_id) -> None:
        super().__init__()
        self.chat_id = chat_id
        self.toke = token
        self.bot = telegram.Bot(token)

    def send_msg(self, msg):
        try:
            self.bot.send_message(self.chat_id, text=msg)
        except Exception as e:
            print(e)
