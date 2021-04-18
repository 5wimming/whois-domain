#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Date    : 2021/04/16
# @Author  : 5wimming
# @dependency package : dnspython, python-whois

import dns.resolver
import whois
import datetime
import csv


def find_domain_info(domain):
    result_data = {'A': [], 'CNAME': [], 'MX': []}
    my_resolver = dns.resolver.Resolver()
    my_resolver.timeout = 30
    # my_resolver.nameservers = [''] # dns server

    for q_type in ['A', 'CNAME', 'MX']:
        try:
            answer = my_resolver.resolve(domain, q_type, raise_on_no_answer=False).rrset
            if answer is not None:
                for i in answer:
                    temp = str(i).split(' ')[-1]
                    temp = temp[0:-1] if temp.endswith('.') else temp
                    result_data[q_type].append(temp)
        except Exception as e:
            print(domain, q_type, e)

    return result_data


def my_whois(domain):
    result_data = {'domain_name': [], 'updated_date': [], 'creation_date': [], 'expiration_date': []}
    try:
        data = whois.whois(domain)
        if data['domain_name']:
            result_data['domain_name'] = data['domain_name'] if isinstance(data['domain_name'], list) else [data['domain_name']]
            if 'updated_date' in data:
                result_data['updated_date'] = list(map(lambda x: x.strftime("%Y-%m-%d %H:%M:%S"), data['updated_date'])) \
                    if isinstance(data['updated_date'], list) else [data['updated_date'].strftime("%Y-%m-%d %H:%M:%S")]
            if 'creation_date' in data:
                result_data['creation_date'] = list(map(lambda x: x.strftime("%Y-%m-%d %H:%M:%S"), data['creation_date'])) \
                    if isinstance(data['creation_date'], list) else [data['creation_date'].strftime("%Y-%m-%d %H:%M:%S")]
            if 'expiration_date' in data:
                result_data['expiration_date'] = list(map(lambda x: x.strftime("%Y-%m-%d %H:%M:%S"), data['expiration_date'])) \
                    if isinstance(data['expiration_date'], list) else [data['expiration_date'].strftime("%Y-%m-%d %H:%M:%S")]
    except Exception as e:
        print(domain, e)

    print(result_data)
    return result_data


def main():
    result_data = []
    with open('./input_data.txt', 'r', encoding='utf-8') as fr:
        input_data = fr.readlines()

    for domain in input_data:
        domain = domain.strip()
        domain_info_data = find_domain_info(domain)
        result_data.append([domain, domain])

        for cname in domain_info_data['CNAME']:
            result_data.append([domain, cname])
        for mx_name in domain_info_data['MX']:
            result_data.append([domain, mx_name])

    whois_data = {}
    time_now_str = datetime.datetime.strptime(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), '%Y-%m-%d %H:%M:%S')

    for i, value in enumerate(result_data):
        print(value)

        domain = value[1]
        # if domain.endswith('5wimming-test.cn'): # balck list
        #     result_data[i] += [' ']*5
        #     continue

        if domain not in whois_data:
            whois_data[domain] = my_whois(domain)

        expiration_date = whois_data[domain]['expiration_date']
        result_data[i].append(' | '.join(whois_data[domain]['domain_name']))
        result_data[i].append(' | '.join(whois_data[domain]['creation_date']))
        result_data[i].append(' | '.join(whois_data[domain]['updated_date']))
        result_data[i].append(' | '.join(expiration_date))

        flag_time = True
        for expiration_time in expiration_date:
            end_time = datetime.datetime.strptime(expiration_time, '%Y-%m-%d %H:%M:%S')
            if (end_time - time_now_str).days < 30:  #
                flag_time = False
                result_data[i].append('Risk time')
                break

        if flag_time:
            result_data[i].append('correct time')

    print(result_data)
    with open('./result.csv', 'w', encoding='utf-8', newline='') as fw:
        csv_w = csv.writer(fw)
        csv_w.writerow(['domain', 'cname or mx', 'domain_name', 'creation_date', 'updated_date', 'expiration_date', 'summary'])
        csv_w.writerows(result_data)


if __name__ == '__main__':
    main()
    # print(find_domain_info('github.com'))
