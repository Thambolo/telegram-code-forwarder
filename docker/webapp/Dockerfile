FROM python:3.9-alpine
WORKDIR /telegram-code-forwarder
COPY ./././requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD [ "flask", "run", "--debug", "--host=0.0.0.0" ]