#!/usr/bin/python3.7

import subprocess
import logging
from telegram import Update
from telegram.ext import ApplicationBuilder, CallbackContext, CommandHandler
from telegram.constants import ParseMode

token = XXXXX

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

async def start(update: Update, context: CallbackContext.DEFAULT_TYPE):
    await context.bot.send_message(chat_id=update.effective_chat.id, text="I'm a Temp Manager bot, you can check the current office temperature with /temp command!")

async def temp(update: Update, context: CallbackContext.DEFAULT_TYPE):
    process_shtemp = subprocess.run("./shtemp", capture_output=True, text=True)
    temp_value = "Temperature: <b>" + process_shtemp.stdout.rstrip() + "</b>°C" 
    await context.bot.send_message(chat_id=update.effective_chat.id, text=temp_value, parse_mode=ParseMode.HTML)

if __name__ == '__main__':
    application = ApplicationBuilder().token(token).build()
    
    start_handler = CommandHandler('start', start)
    temp_handler = CommandHandler('temp', temp)
    
    application.add_handler(start_handler)
    application.add_handler(temp_handler)
    
    application.run_polling()
