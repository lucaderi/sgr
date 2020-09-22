import click
import requests
import json


@click.command()
@click.argument('token')
@click.option('--conf', default='config.json',
              help='configuration file for influxdb, telegram default is config.json')
def tconf(token, conf):
    url = "https://api.telegram.org/bot{}/getUpdates".format(token)
    r = requests.get(url=url)
    if r.status_code == 200:
        data = r.json()
        chat_id = data['result'][0]['message']['chat']['id']
        with open(conf, "r+") as f:
            config = json.load(f)
            f.seek(0)
            config["telegram"]["token"] = token
            config["telegram"]["chatid"] = chat_id
            json.dump(config, f, indent=4, sort_keys=True)
            print("[*] Telegram successfully configured in", conf)
    else:
        print("[!] Error: ", r)


if __name__ == '__main__':
    tconf()
