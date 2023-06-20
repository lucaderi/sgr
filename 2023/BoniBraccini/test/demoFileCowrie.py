import random
import os
import time

def copy_lines(input_file1, output_file1):
    with open(input_file1, 'r') as file1:
        lines1 = file1.readlines()
    if os.path.exists(output_file1):
       os.remove(output_file1)


    while lines1 :
        line1 = lines1.pop(0)
        line2 = lines1.pop(1)
        line3 = lines1.pop(2)

        with open(output_file1, 'a') as file1:
            file1.write(line1)
            file1.write(line2)
            file1.write(line3)

        interval = 60
        time.sleep(interval)

if __name__ == '__main__':
    input_file1 = 'Cowrie_logs_test.json'
    output_file1 = 'syncedLog.json'

    copy_lines(input_file1, output_file1)
