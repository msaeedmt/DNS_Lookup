import binascii
import csv
import re
import socket
import os.path
import random


################################## section 2.3
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# port = 3126
# s.connect(('localhost', port))
# z = 'Message from client'
# s.sendall(z.encode())
# s.close()
###############################################

def send_udp_message(message, address, port=53):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


def build_message(type="A", address=""):

    ID = random.randint(1, 65534)
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 0
    RA = 0
    Z = 0
    RCODE = 0
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0
    QTYPE = get_type(type)
    QCLASS = 1

    query_params = str(QR) + str(OPCODE).zfill(4) + str(AA) + str(TC) + str(RD) + str(RA) + str(Z).zfill(3) + str(
        RCODE).zfill(4)
    query_params = "{:04x}".format(int(query_params, 2))

    message = ""
    message += "{:04x}".format(ID)
    message += query_params
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    addr_parts = address.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()
    message += "00"

    message += QTYPE

    message += "{:04x}".format(QCLASS)

    return message


def decode_message(message):
    res = []

    ID = message[0:4]
    query_params = message[4:8]

    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20]
    ARCOUNT = message[20:24]

    params = "{:b}".format(int(query_params, 16)).zfill(16)

    recursive_capability = params[8:9]
    RCODE = params[12:16]
    is_truncated = params[6:7]

    # if int(is_truncated) == 1:
    #     print("The message is Truncated !")
    #     exit()
    if int(RCODE, 16) != 0:
        print("Server error")
        exit()

    QUESTION_SECTION_STARTS = 24
    question_parts = parse_parts(message, QUESTION_SECTION_STARTS, [])

    QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4
    QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]

    res.append("\n------------------------------ QUESTION SECTION ----------------------------------")
    res.append("ID: " + ID)
    res.append("QTYPE: " + QTYPE + " (\"" + get_type(int(QTYPE, 16)) + "\")")
    # res.append("RECURSIVE CAPABILITY: " + recursive_capability)
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4

    ANCOUNT_INT = int(ANCOUNT, 16)
    NSCOUNT_INT = int(NSCOUNT, 16)
    ARCOUNT_INT = int(ARCOUNT, 16)

    NUM_ANSWERS = max([ANCOUNT_INT, NSCOUNT_INT, ARCOUNT_INT])
    if NUM_ANSWERS > 0:
        final_IPs.clear()
        res.append("\n------------------------------ ANSWER SECTION ------------------------------")

        res.append(">>>>>>> Answers <<<<<<<<")
        if ANCOUNT_INT == 0:
            res.append("No Answers ...\n")

            res.append(">>>>>>> Authorative <<<<<<<<")
            if NSCOUNT_INT == 0:
                res.append("No Authorative ...\n")
            else:
                record_res, ANSWER_SECTION_STARTS, datas = get_record(message, ANSWER_SECTION_STARTS, NSCOUNT_INT)
                res.extend(record_res)

            res.append(">>>>>>> Additional <<<<<<<<")
            if ARCOUNT_INT == 0:
                res.append("No Additional ...\n\n")
            else:
                record_res, ANSWER_SECTION_STARTS, datas = get_record(message, ANSWER_SECTION_STARTS, ARCOUNT_INT)
                res.extend(record_res)
                if ANCOUNT_INT == 0:
                    for data in datas:
                        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data) != None:
                            packet_request(req_message, data)
                            break
        else:
            record_res, ANSWER_SECTION_STARTS, datas = get_record(message, ANSWER_SECTION_STARTS, ANCOUNT_INT)
            res.extend(record_res)
            final_IPs.extend(datas)

    all_responses.append(res)

    return "\n".join(res)


def get_type(type):
    return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]


types = [
    "NOT EXIST",
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT"
]


def get_record(message, start, parts_count, ):
    res = []
    decoded_datas = []
    for i in range(parts_count):
        if (start < len(message)):
            ATYPE = message[start + 4:start + 8]
            TTL = int(message[start + 12:start + 20], 16)
            RDLENGTH = int(message[start + 20:start + 24], 16)
            RDDATA = message[start + 24:start + 24 + (RDLENGTH * 2)]

            if ATYPE == get_type("A"):
                octets = [RDDATA[i:i + 2] for i in range(0, len(RDDATA), 2)]
                RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))
            else:
                RDDATA_decoded = ".".join(
                    map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(RDDATA, 0, [])))

            start = start + 24 + (RDLENGTH * 2)

            res.append("# ANSWER " + str(i + 1))
            res.append("TTL: " + str(TTL))
            res.append("RDDATA " + RDDATA_decoded + "\n")
            decoded_datas.append(RDDATA_decoded)
    return res, start, decoded_datas


def parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]

    if len(part_len) == 0:
        return parts

    part_end = part_start + (int(part_len, 16) * 2)
    parts.append(message[part_start:part_end])

    if message[part_end:part_end + 2] == "00" or part_end > len(message):
        return parts
    else:
        return parse_parts(message, part_end, parts)


def packet_request(message, address='198.41.0.4'):
    response = send_udp_message(message, address)
    # print("\nResponse:\n" + response)
    # print("\nResponse (decoded):" + decode_message(response))
    decode_message(response)


def request_from_file(filename, address="198.41.0.4"):
    rows = []
    output_packets = []
    with open(filename, 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        fields = next(csvreader)

        for row in csvreader:
            rows.append(row)

    for url_type in rows:
        message_req = build_message(url_type[1], url_type[0])
        response = send_udp_message(message_req, address)
        output_packets.append([message_req, response])

    filename = "output_packets.csv"
    fields = ['request', 'respond']
    with open(filename, 'w',newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        csvwriter.writerow(fields)

        csvwriter.writerows(output_packets)
        print("Successfully has been written to {}".format(filename))


#####################################################################################
dns_request_logs = {}
new_cached_dnss = []
cached_dnss = {}

cache_filname = "cached_dnss"
logs_filename = "logs_request"

if not os.path.isfile(cache_filname):
    fields = ['Name ADRESS', 'IP']
    with open(cache_filname, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        csvwriter.writerow(fields)

if os.path.isfile(logs_filename):
    with open(logs_filename, 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        fields = next(csvreader)
        for row in csvreader:
            if len(row) > 0:
                dns_request_logs[row[0]] = int(row[1])

with open(cache_filname, 'r') as csvfile:
    csvreader = csv.reader(csvfile)

    fields = next(csvreader)
    for row in csvreader:
        if len(row) > 0:
            cached_dnss[row[0]] = row[1]

print("Sample command : \'google.com type=A 1.1.1.1\' (second and third parameters are optional)")
print("Reading From File sample command : \'file \"csvFilename\"\'")
print("> ", end='')
command = input()
params = command.split(' ')
default_type = "A"

while (params[0] != 'quit'):

    final_IPs = []
    all_responses = []

    type = None
    url = None
    address = None

    if params[0] == 'file':
        if len(params) > 2:
            print("Filename needed!")
        request_from_file(params[1])
    else:
        if len(params) == 1:
            type = default_type
        elif len(params) >= 2:
            type_params = params[1].split('=')
            if len(type_params) != 2:
                print("Wrong Command format!")
                exit()
            if type_params[0] != "type":
                print("Wrong Command format!")
                exit()
            if type_params[1] not in types:
                print("Wrong type!")
                exit()
            type = type_params[1]

        if len(params) >= 3:
            address_param = params[2]
            if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', address_param) != None:
                address = address_param
            else:
                print('IP address is wrong!')

        url = params[0]
        if url in cached_dnss.keys():
            print("IP:", cached_dnss[url].split(' ')[0])
            dns_request_logs[url] += 1
        else:
            req_message = build_message(type, url)
            print("NAME ADDRESS : {}".format(url))

            if address is not None:
                packet_request(req_message, address)
            else:
                packet_request(req_message)

            for i in range(len(all_responses) - 1, -1, -1):
                print("\n".join(all_responses[i]))

            print('--------------------- result ---------------------')
            print("NAME ADDRESS : {} ".format(url))
            for final_IP in final_IPs:
                print("IP:", final_IP)

            if url in dns_request_logs.keys():
                dns_request_logs[url] += 1
                if dns_request_logs[url] > 10 and url not in cached_dnss.keys():
                    new_cached_dnss.append([url, " ".join(final_IPs)])
            else:
                dns_request_logs[url] = 1

    print("\n> ", end='')
    params = input().split(' ')
print(dns_request_logs)
print(new_cached_dnss)

fields = ['Name ADRESS', 'NUMBER OF REQUESTED TIMES']
with open(logs_filename, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)

    csvwriter.writerow(fields)
    for url in dns_request_logs.keys():
        csvwriter.writerow([url, dns_request_logs[url]])

    csvfile.close()

with open(cache_filname, 'a', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)

    for row in new_cached_dnss:
        csvwriter.writerow(row)

    csvfile.close()

