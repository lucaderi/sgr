import random
import time
import os

def copy_lines(input_file2, output_file2):
    with open(input_file2, 'r') as file2:
        lines2 = file2.readlines()
    if os.path.exists(output_file2):
       os.remove(output_file2)


    while lines2:
        lineDion = lines2.pop(0)

        with open(output_file2, 'a') as file2:
            file2.write(lineDion)

        interval = 30
        time.sleep(interval)

if __name__ == '__main__':
    input_file2 = 'Dionaea_logs_test.json'
    output_file2 = 'syncedLogDion.json'

    copy_lines(input_file2, output_file2)
