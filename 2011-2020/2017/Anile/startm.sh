#
#		DNSmonitor
#   Copyright (C) 2017  Simone Anile simone.anile@gmail.com
#
#		This file is part of DNSmonitor.
#
#   DNSmonitor is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   DNSmonitor is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with DNSmonitor.  If not, see <http://www.gnu.org/licenses/>.
#
mkdir -p logs
if [ $? -eq 0 ]
then
  make clean && make && sudo ./dnsa -v -i wlan0 \
    -m -t simone.anile@gmail.com -f simone.anile@tiscali.it \
    -o "Allarme DNS!!!" -s smtp.tiscali.it -u simone.anile@tiscali.it \
    -p Dnsgr171
else
  echo "*************************"
  echo "*  _____  _   _  _____  *"
  echo "* |  __ \| \ | |/ ____| *"
  echo "* | |  | |  \| | (___   *"
  echo "* | |  | |     |\___ \  *"
  echo "* | |__| | |\  |____) | *"
  echo "* |_____/|_| \_|_____/  *"
  echo "*        monitor        *"
  echo "*************************"
  echo "Errore durante la creazione della cartella!"
  echo "Controlla di avere i permessi per creare una cartella in:"
  pwd
fi
