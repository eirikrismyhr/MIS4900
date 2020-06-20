import subprocess
import csv


def line_count(filename):
    return int(subprocess.check_output(['wc', '-l', filename]).split()[0])


def domain_num(filename):
    logfile = open(filename, "r")
    values = []
    i = 0
    for line in logfile:
        print(i)
        fields = line.split(" ")
        domain_name = remove_chars(fields[4])
        if domain_name not in values:
            values.append(domain_name)
        i += 1
    return len(values)


def remove_chars(string):
    chars = [')', '(', ':']
    delete_dict = {sp_character: '' for sp_character in chars}
    delete_dict[' '] = ''
    table = str.maketrans(delete_dict)
    string = string.translate(table)
    return str(string)


def find_rrtypes(filename):
    types = []
    with open(filename, 'r') as in_file:
        reader = csv.reader(in_file, delimiter=',')
        for line in reader:
            if line[10] not in types:
                types.append(line[10])
    return types

print(line_count("datasets/anon_dns_records.txt"))
#print(domain_num("datasets/anon_dns_records.txt"))
print(find_rrtypes("datasets/eidsiva_test.csv"))

