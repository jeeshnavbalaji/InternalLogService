# InternalLogService
Python service for Internal logs

Activte the virtualenv

-internallogservice\Scripts\activate

If there are any db related changes need to run following commands
 -Python manage.py makemigrations
 -Python manage.py migrate

Then run python server
- python manage.py runserver

We have to make a user, you can make user either with the admin panel or using the command line.
 using command line > python manage.py createsuperuser
 then enter the username, email and password
 
 Then run the server using > python manage.py runserver (It will defaultly run in 8000 port)
 In order to change the port run the cmd > python manage.py runserver 8001
