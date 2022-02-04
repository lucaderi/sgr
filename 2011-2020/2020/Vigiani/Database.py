#
#   File in cui scrivo i dati
#
file = None

#
#   Se True allora scrivo il nome delle colonne
#
first = True

#
#   Id della riga
#
i = 1

#
#   Creo il file in cui scriverò i dati
#
def create():
    global file
    file = open("data.csv", "w")

#
#   Chiudo il file
#
def close():
    global file
    file.close()

#
#   Scrive i dati in formato csv nel file.
#   Le varie colonne sono separate dal carattere: ;
#   I vari elementi di una colonna sono separati dal carattere: ,
#
def update(values):
    global first

    if first is True:
        col = convertToColumns(values)
        file.write(col)
        first = False

    row = convertToRow(values)
    file.write(row)

    print("Success Update")

#
#   Crea la riga che indica le colonne
#
def convertToColumns(keys):
    col = "index;"
    for key in keys:
        col += str(key) + ";"
    return col[:-1:] + "\n"

#
#   Crea la riga associata ai dati appena elaborati
#
def convertToRow(values):
    global i

    row = "" + str(i) + ";"
    for key in values:
        j = 0
        for val in values[key].split('%'):
            if j != 0:
                row += str(val) + ","
            else:
                j = j + 1
        row = row[:-1:] + ";"
    i = i + 1
    return row[:-1:] + "\n"
