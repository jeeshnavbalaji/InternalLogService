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
from internallogservice.core.models import EmailAlerts, DomainFields, PacketFields
import schedule
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def login(request):
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
    return Response({'token': token.key},

                    status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def email_alert(request):
    print(request.data)
    email = request.data['email'][0]
    send_log = request.data['sendLog']
    day_of_week = request.data['dayOfWeek']
    send_time = request.data['time']
    file_format = request.data['fileFormat']
    include_all = request.data['includeAll']
    log_type = 'domain'
    created_date = datetime.now()
    sent_date = datetime.now()
    email_alert_object = EmailAlerts(1, email, send_log, day_of_week, send_time, file_format, include_all, log_type,
                                     created_date, sent_date)
    email_alert_object.save()
    # scheduler setup
    if send_log == "daily":
        schedule.every().day.at(send_time).do(send_email)
    while True:
        schedule.run_pending()
        time.sleep(1)
    return Response(status=HTTP_200_OK)


def send_email():
    # email_alert_object = EmailAlerts.objects.all()
    fromaddr = "jbachu@loginsoft.com"
    toaddr = "jbachu@loginsoft.com"

    # instance of MIMEMultipart
    msg = MIMEMultipart()

    # storing the senders email address
    msg['From'] = fromaddr

    # storing the receivers email address
    msg['To'] = toaddr

    # storing the subject
    msg['Subject'] = "test Python script with attachment"

    # string to store the body of the mail
    body = "PFA the log file"

    # attach the body with the msg instance
    msg.attach(MIMEText(body, 'plain'))

    # open the file to be sent
    filename = "E:/ELK_example/system_log.zip"
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
    s = smtplib.SMTP('smtp.office365.com', 587)

    # start TLS for security
    s.starttls()

    # Authentication
    s.login(fromaddr, "@07711a0514P")

    # Converts the Multipart msg into a string
    text = msg.as_string()

    # sending the mail
    s.sendmail(fromaddr, toaddr, text)

    # terminating the session
    s.quit()


@csrf_exempt
@api_view(["GET"])
def sample_api(request):
    data = {'sample_data': 123}
    return Response(data, status=HTTP_200_OK)
