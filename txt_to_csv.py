import csv


def import_dataset(filename):
    with open(filename, 'r') as in_file:
        stripped = (line.strip() for line in in_file)
        lines = (line.split(" ") for line in stripped if line)
        unwanted = ['"', '""']
        with open('datasets/eidsiva_test.csv', 'w') as out_file:
            writer = csv.writer(out_file)
            writer.writerow(('date', 'time', 'user', 'src', 'domain_par', 'view', 'ntp-stealth', 'query', 'domain_name',
                             'in', 'rr_type', '+', 'dst'))
            for line in lines:
                write = True
                for field in line:
                    for char in unwanted:
                        if char in field:
                            write = False
                if write:
                    writer.writerow(line)
                else:
                    print(line)


import_dataset("datasets/anon_dns_records.txt")
