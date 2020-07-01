from django.contrib.auth import authenticate
from django.utils.datetime_safe import datetime
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_403_FORBIDDEN)
from rest_framework.response import Response
from internallogservice.core.models import EmailAlerts, GMCApiKey
from schedule import default_scheduler as schedule
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import json
import csv
import requests
from django.core import serializers
from pytz import timezone
from tzlocal import get_localzone
import logging
from traceback import format_exc
from datetime import timedelta
from timeloop import Timeloop
from config import config_settings as settings

logger = logging.getLogger('schedule')

tl = Timeloop()
try:
    gmc_url = settings.URL
    # print("Gmc host-> ", settings.URL, "auth_key-> ", key)
    from_email = settings.FROM_EMAIL
    password = settings.PASSWORD
    smtp_servers = settings.SMTP_SERVERS
    email_host = settings.MAIL_HOST
    if email_host.lower() in smtp_servers.keys():
        smtp_server = smtp_servers[email_host]
        print("smtp server->", smtp_server)
    if email_host.lower() == 'att' or email_host.lower() == 'verizon':
        port = settings.port[1]
    else:
        port = settings.port[0]
    print("port->", port)
except Exception:
    logger.error(format_exc())


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def gmckey_setup(request):
    global key
    key = request.data["apikey"]
    headers = {
                "accept": "application/json",
                "x-api-key": key
            }
    print(key)
    data = requests.get("https://gmc.banduracyber.com/api/v1/asn", headers=headers)
    print("Data from gmc->", data)
    if data.status_code == 200:
        gmc_api_key_object = GMCApiKey(id=1, api_key=key)
        gmc_api_key_object.save()
        return Response(data, status=HTTP_200_OK)
    else:
        return Response(json.loads(data.text)['message'], status=data.status_code)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def login(request):
    global key
    api_key = ''
    username = request.data.get("username")
    password = request.data.get("password")
    if username is None or password is None:
        return Response({'error': 'Please provide both username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid Credentials'},
                        status=HTTP_403_FORBIDDEN)
    token, _ = Token.objects.get_or_create(user=user)
    try:
        data = GMCApiKey.objects.get()
    except GMCApiKey.DoesNotExist:
        data = None
    print(data)
    if data:
        api_key = str(data)
        key = api_key
    print("Api key->", api_key)
    return Response({'token': token.key, 'gmc_api_key': api_key}, status=HTTP_200_OK)


@csrf_exempt
@api_view(["DELETE"])
@permission_classes((AllowAny,))
def delete_email_alert(request):
    print(request.data)
    EmailAlerts.objects.get(id=request.data['id']).delete()
    data = serializers.serialize('json', EmailAlerts.objects.all())
    data_json = json.loads(data)
    print(data_json)
    return Response(data_json, status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def email_alert(request):
    print(request.data)
    print("host->", request.get_host())
    print("is_secure->", request.is_secure())
    for mail in request.data['email']:
        email = mail
        send_log = request.data['sendLog']
        day_of_week = request.data['dayOfWeek']
        send_time = request.data['time']
        file_format = request.data['fileFormat']
        include_all = request.data['includeAll']
        log_type = request.data['logType']
        created_date = datetime.now()
        sent_date = datetime.now()
        domain_domain = None
        domain_proto = None
        domain_source = None
        domain_destination = None
        domain_action = None
        domain_reason = None
        domain_device = None
        packet_country = None
        packet_as_name = None
        packet_proto = None
        packet_source = None
        packet_destination = None
        packet_direction = None
        packet_action = None
        packet_category = None
        packet_reason = None
        packet_lists = None
        packet_group = None
        packet_host_name = None
        if log_type == 'packet' and not include_all:
            packet_country = request.data['packet']['country']
            packet_as_name = request.data['packet']['asName']
            packet_proto = request.data['packet']['proto']
            packet_source = request.data['packet']['source']
            packet_destination = request.data['packet']['destination']
            packet_direction = request.data['packet']['direction']
            packet_action = request.data['packet']['action']
            packet_category = request.data['packet']['category']
            packet_reason = request.data['packet']['reason']
            packet_lists = request.data['packet']['list']
            packet_group = request.data['packet']['group']
            packet_host_name = request.data['packet']['hostName']

        if log_type == 'domain' and not include_all:
            domain_domain = request.data['domain']['domain']
            domain_proto = request.data['domain']['proto']
            domain_source = request.data['domain']['source']
            domain_destination = request.data['domain']['destination']
            domain_action = request.data['domain']['action']
            domain_reason = request.data['domain']['reason']
            domain_device = request.data['domain']['hostName']

        email_alert_object = EmailAlerts(email=str(email), send_log=send_log, day_of_week=day_of_week, time=send_time,
                                         file_format=file_format, include_all=include_all, log_type=log_type,
                                         created_date=created_date, sent_date=sent_date, packet_country=packet_country,
                                         packet_asName=packet_as_name, packet_proto=packet_proto,
                                         packet_source=packet_source, packet_destination=packet_destination,
                                         packet_direction=packet_direction, packet_action=packet_action,
                                         packet_category=packet_category, packet_reason=packet_reason,
                                         packet_list=packet_lists, packet_group=packet_group,
                                         packet_device=packet_host_name, domain_domain=domain_domain,
                                         domain_proto=domain_proto, domain_source=domain_source,
                                         domain_destination=domain_destination, domain_action=domain_action,
                                         domain_reason=domain_reason, domain_device=domain_device)
        email_alert_object.save()

    utc_datetime = datetime.now(timezone('UTC'))
    send_time_parts = send_time.split(":")
    new_datetime = utc_datetime.replace(hour=int(send_time_parts[0]), minute=int(send_time_parts[1]))
    # new_datetime_parts = str(new_datetime.split("."))
    # utc_datetime_timestamp = float(new_datetime.strftime("%s"))
    local_datetime_converted = new_datetime.astimezone(get_localzone())
    schedule_at_time = "{0:0>2}".format(str(local_datetime_converted.hour))+":" +\
                       "{0:0>2}".format(str(local_datetime_converted.minute))
    print("Time to set at method perameter-> ", schedule_at_time)
    # scheduler setup
    # scheduler = EmailScheduler()
    if send_log == "daily":
        schedule.every().day.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())
    if send_log == "weekly" or send_log == "monthly":
        if day_of_week == "sunday":
            schedule.every().sunday.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())
        if day_of_week == "monday":
            schedule.every().monday.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())
        if day_of_week == "tuesday":
            schedule.every().tuesday.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())
        if day_of_week == "wednesday":
            schedule.every().wednesday.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())
        if day_of_week == "thursday":
            schedule.every().thursday.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())
        if day_of_week == "friday":
            schedule.every().friday.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())
        if day_of_week == "saturday":
            schedule.every().saturday.at(schedule_at_time).do(send_email, request.get_host(), request.is_secure())

    # email_cron = CronTab(tab="""* * * * * python email_schedule.py""")
    # job = email_cron.new(command='* * * * * python email_schedule.py')
    # job.minute.every(1)
    # job.every_reboot()
    # for job in email_cron:
    #     print("cron jobs->", job)
    # email_cron.write()
    # check_pending()
    # schedule_thread = threading.Thread(target=check_pending(), args=(10,))
    # schedule_thread.start()
    # while True:
    #     schedule.run_pending()
    #     time.sleep(1)
    # if __name__ == "__main__":
    try:
        print("timeloop jobs", list(tl.jobs))
        tl.start()
    except Exception:
        logger.error(format_exc())
    return Response(status=HTTP_200_OK)


@csrf_exempt
@api_view(["GET"])
@permission_classes((AllowAny,))
def edit_email_alert(request):
    data = serializers.serialize('json', EmailAlerts.objects.all())
    data_json = json.loads(data)
    print(data_json)
    return Response(data_json, status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def get_from_gmc(request):
    if 'policy' in request.data:
        request_url = gmc_url+request.data['policy']
        headers = {
            "accept": "application/json",
            "x-api-key": key
        }
    if 'country' in request.data:
        request_url = gmc_url+request.data['country']
        headers = {
            "accept": "application/json",
            "x-api-key": key
        }
    if 'whitelist' in request.data:
        request_url = gmc_url+request.data['whitelist']+'/ipv4'
        headers = {
            "accept": "application/json",
            "x-api-key": key,
            "X-Fields": "{uuid, name, type, ip_count}"
        }
    if 'blacklist' in request.data:
        request_url = gmc_url+request.data['blacklist']+'/ipv4'
        headers = {
            "accept": "application/json",
            "x-api-key": key,
            "X-Fields": "{uuid, name, type, ip_count}"
        }
    if 'type' in request.data:
        request_url = gmc_url+"policy/"+request.data['policyId']+"/countries/"+request.data['type']
        headers = {
            "accept": "application/json",
            "x-api-key": key
        }
    data = requests.get(request_url, headers=headers)
    print("Data from gmc->", data.json())
    return Response(data.json(), status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def add_country_to_allowed_or_denied(request):
    url = gmc_url+"policy/"+request.data['policy_uuid']+"/countries/"
    if 'allowed' in request.data['type']:
        request_url = url+request.data['type']
    if 'denied' in request.data['type']:
        request_url = url+request.data['type']

    params = {
        'codes': request.data['country_code']
    }
    headers = {
        "accept": "application/json",
        "x-api-key": key
    }
    data = requests.patch(request_url, params=params, headers=headers)
    print("Data from gmc after allowed or denied->", data.json())
    return Response(data.json(), status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def add_or_delete_to_whitelist_and_blacklist(request):
    list_type_lower = request.data['list_type'].lower()
    request_url = gmc_url+list_type_lower+"/ipv4/"+request.data['group_uuid']+"/addrs"
    params = {
        'ip_addr': request.data['ip_address'],
        'mask_bits': 32
    }
    headers = {
        "accept": "application/json",
        "x-api-key": key
    }
    if request.data['action_type'] == 'Deleted':
        set_address_url = request_url+'/'+request.data['ip_address']+'/32'
        data = requests.delete(set_address_url, headers=headers)
    else:
        data = requests.post(request_url, params=params, headers=headers)
    print("Data from gmc after update in list->", data.json())
    return Response(data.json(), status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def check_ipaddress_in_listgroup(request):
    response_data = []
    request_url = gmc_url+request.data['grouptype']+"/ipv4/"+request.data['group_uuid']+"/addrs"
    response_data.append(request.data['group_uuid'])
    headers = {
        "accept": "application/json",
        "x-api-key": key
    }
    data = requests.get(request_url, headers=headers)
    response_data.append(data.json())
    print('Grouplist ipaddress++++++++++++++++++++++++++++++++++++++++++++++')
    print(request_url)
    print("Data from grouplist->", response_data)
    return Response(response_data, status=HTTP_200_OK)


def send_email(host, is_secure):
    print("inside send_email() method")
    email_alert_object = json.loads(serializers.serialize('json', EmailAlerts.objects.all()))
    fromaddr = from_email
    toaddr = ""
    days_difference = None
    str_time = "{0:0>2}".format(str(datetime.utcnow().hour)) + ":" + "{0:0>2}".format(str(datetime.utcnow().minute)) + ":00"
    print("str_time->", str_time)
    for alert_obj in email_alert_object:
        # print(alert_obj)
        # print("time now", str_time)
        # print("before if: ", alert_obj['fields']['time'])
        if alert_obj['fields']['sent_date']:
            sent_date = alert_obj['fields']['sent_date'].split("T")
            # print("alert_obj date->", alert_obj['fields']['sent_date'])
            # print("date from db->", datetime.strptime(sent_date[0], '%Y-%m-%d'))
            days_difference = datetime.now() - datetime.strptime(sent_date[0], '%Y-%m-%d')
            # print("sent days->", days_difference.days)
        if alert_obj['fields']['time'] == str_time and alert_obj['fields']['send_log'] == 'daily':
            print("daily time->", alert_obj['fields']['time'])
            toaddr = alert_obj['fields']['email']
            email(fromaddr, toaddr, alert_obj, host, is_secure)
            # print("daily: ", toaddr)

        if alert_obj['fields']['send_log'] == 'weekly' and alert_obj['fields']['time'] == str_time:
            print("weekly->", alert_obj['fields']['time'])
            if alert_obj['fields']['sent_date'] and days_difference.days == 7:
                toaddr = alert_obj['fields']['email']
                email(fromaddr, toaddr, alert_obj, host, is_secure)
                # print("weekly:", toaddr)
            elif not alert_obj['fields']['sent_date']:
                toaddr = alert_obj['fields']['email']
                email(fromaddr, toaddr, alert_obj, host, is_secure)
                # print("weekly:", toaddr)

        if alert_obj['fields']['send_log'] == 'monthly' and alert_obj['fields']['time'] == str_time:
            print("monthly time->", alert_obj['fields']['time'])
            if alert_obj['fields']['sent_date'] and days_difference.days == 30:
                toaddr = alert_obj['fields']['email']
                email(fromaddr, toaddr, alert_obj, host, is_secure)
                # print("monthly:", toaddr)
            elif not alert_obj['fields']['sent_date']:
                toaddr = alert_obj['fields']['email']
                email(fromaddr, toaddr, alert_obj, host, is_secure)
                # print("monthly:", toaddr)


def email(fromaddr, to, obj, host, is_secure):
    print("inside email() method")
    # get data from Elasticsearch
    url = ""
    es_data = {}
    host_arr = host.split(":")
    elasticsearch_host = settings.ELASTICSEARCH_HOST
    print("running host->", elasticsearch_host)
    if host_arr[0].lower() == 'localhost' or host_arr[0] == '127.0.0.1':
        elasticsearch_host = host_arr[0]
    print("ElasticSearch host-> ", elasticsearch_host)
    if is_secure:
        url = "https://" + elasticsearch_host + ":9200/"
    else:
        url = "http://" + elasticsearch_host + ":9200/"
    es_url = url + "logstash-" + obj['fields']['log_type'] + "/_search"
    if not obj['fields']['include_all']:
        get_request_query(obj)
        es_data = requests.post()
    else:
        print("inside es get else condition:", es_url)
        es_data = requests.get(es_url)
        data = es_data.json()
        create_file(data)
        print("Data from Elasticsearch->")
        print("total docs->", data['hits']['total']['value'], "Relation->", data['hits']['total']['relation'])
        print("Device name->", data['hits']['hits'][0]['_source']['HName'])

    # instance of MIMEMultipart
    print("to addresses", to)
    msg = MIMEMultipart()

    # storing the senders email address
    msg['From'] = fromaddr

    # storing the receivers email address
    msg['To'] = to

    # storing the subject
    msg['Subject'] = "Internal logs email alert"

    # string to store the body of the mail
    body = "PFA the log file"

    # attach the body with the msg instance
    msg.attach(MIMEText(body, 'plain'))

    # open the file to be sent
    filename = "./logfile.csv"
    attachment = open(filename, "rb")

    # instance of MIMEBase and named as p
    p = MIMEBase('application', 'octet-stream')

    # To change the payload into encoded form
    p.set_payload(attachment.read())

    # encode into base64
    encoders.encode_base64(p)

    p.add_header('Content-Disposition', "attachment; filename= %s" % filename)

    # attach the instance 'p' to instance 'msg'
    msg.attach(p)

    # creates SMTP session
    # s = smtplib.SMTP('smtp.office365.com', port)
    try:
        s = smtplib.SMTP(smtp_server, port)
        # start TLS for security
        s.starttls()
        print("from address email before login->", fromaddr)
        # Authentication
        s.login(fromaddr, password)

        # Converts the Multipart msg into a string
        text = msg.as_string()

        # sending the mail
        s.sendmail(fromaddr, to, text)

        print("mail sent->")
        # terminating the session
        s.quit()
    except smtplib.SMTPException:
        logger.error("Error: unable to send email", format_exc())


def get_request_query(obj):
    query_obj = {}
    if obj['fields']['log_type'] == "packet":
        query_obj = obj['fields']['packet']
    elif obj['fields']['log_type'] == "domain":
        query_obj = obj['fields']['domain']

    if not query_obj:
        query_obj = obj
    else:
        query_obj = {k: v for k, v in query_obj.items() if "Select" not in v}

    fields_arr = list(query_obj.keys())
    query_string = ""
    for v in list(query_obj.values()):
        if not query_string:
            query_string = v
        else:
            query_string += "AND " + v

    start_date = ""
    if not obj['fields']['sent_date']:
        created = obj['fields']['created_date'].split(".")
        start_date = created[0]
    else:
        sent = obj['fields']['sent_date'].split(".")
        start_date = sent[0]
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "fields": [
                                fields_arr
                            ],
                            "query": query_string
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "time_zone": "+01:00",
                                "gte": start_date,
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ]
    }
    return query


def create_file(data_obj):
    packet_json = {}
    domain_json = {}
    packet_logs = []
    domain_logs = []
    # f = open("./logfile.json", "w")
    for data in data_obj['hits']['hits']:
        if data['_index'] == "logstash-packet":
            denied_category = ""
            matched_category = ""
            threatlists = ""
            whitelists = ""
            blacklists = ""
            if 'denied_categories' in data['_index']:
                denied_category = data['_source']['denied_categories']
            if 'matched_categories' in data['_index']:
                denied_category = data['_source']['matched_categories']
            if 'threatlists' in data['_index']:
                threatlists = data['_source']['threatlists']
            if 'whitelists' in data['_index']:
                whitelists = data['_source']['whitelists']
            if 'blacklists' in data['_index']:
                blacklists = data['_source']['blacklists']
            packet_obj = {
                "timestamp": data['_source']['timestamp'],
                "country": data['_source']['Country'],
                "as_name": data['_source']['asName'],
                "protocol": data['_source']['Proto'],
                "source_ip": data['_source']['source'],
                "destination_ip": data['_source']['destination'],
                "direction": data['_source']['Direction'],
                "action": data['_source']['Action'],
                "denied_category": denied_category,
                "matched_category": matched_category,
                "reason": data['_source']['reason'],
                "threatlists": threatlists,
                "whitelists": whitelists,
                "blacklists": blacklists,
                "group": data['_source']['Group'],
                "device": data['_source']['HName']
            }
            packet_logs.append(packet_obj)

        if data['_index'] == "logstash-domain":
            domain_obj = {
                "timestamp": data['_source']['timestamp'],
                "domain": data['_source']['Domain'],
                "protocol": data['_source']['Proto'],
                "source_ip": data['_source']['Source'],
                "destination_ip": data['_source']['DST'],
                "action": data['_source']['Action'],
                "reason": data['_source']['Reason'],
                "device": data['_source']['HName']
            }
            domain_logs.append(domain_obj)
        if packet_logs:
            packet_json = packet_logs
            # f.write(str(packet_json))
        if domain_logs:
            domain_json = domain_logs
            # f.write(str(domain_json))

    # f.close()
    print("After json file creation")
    # open a file for writing
    data_file = open("./logfile.csv", 'w+', newline='')
    # create the csv writer object
    csv_writer = csv.writer(data_file)
    count = 0
    # packet logs
    if data['_index'] == "logstash-packet":
        for packet in packet_json:
            if count == 0:
                header = packet.keys()
                csv_writer.writerow(header)
                count += 1
            # Writing data of CSV file
            csv_writer.writerow(packet.values())
        data_file.close()
        print("After csv file creation")
    # domain logs
    if data['_index'] == "logstash-domain":
        for domain in domain_json:
            if count == 0:
                header = domain.keys()
                csv_writer.writerow(header)
                count += 1
            # Writing data of CSV file
            csv_writer.writerow(domain.values())
        data_file.close()
        print("After csv file creation")


@tl.job(interval=timedelta(seconds=1))
def check_pending():
    logger.info("Checking schedule pending jobs")
    try:
        schedule.run_pending()
    except Exception:
        logger.error(format_exc())


@csrf_exempt
@api_view(["GET"])
def sample_api(request):
    data = {'sample_data': 123}
    return Response(data, status=HTTP_200_OK)
