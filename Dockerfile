FROM python:3.7
RUN mkdir /code
WORKDIR /code
COPY . /code/
RUN pip install -r requirements.txt
EXPOSE 8000
CMD ["python", "manage.py", "runsslserver", "0.0.0.0:8000"]
