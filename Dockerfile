FROM python:3.7
RUN mkdir /code
WORKDIR /code
COPY . /code/
RUN pip install -r requirements.txt
EXPOSE 8000
RUN apt-get update
RUN apt-get install -y cron
RUN python manage.py crontab add
CMD service cron start ; python manage.py runsslserver 0.0.0.0:8000
