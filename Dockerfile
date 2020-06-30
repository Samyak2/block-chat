# Use the official lightweight Python image.
# https://hub.docker.com/_/python
FROM python:3.7-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Copy local code to the container image.
ENV APP_HOME /app
WORKDIR $APP_HOME
COPY ./requirements.txt ./requirements.txt
# Install production dependencies.
RUN pip install -r ./requirements.txt

# Environment variables
ARG node_url
ARG node_secret
ENV NODE_ADDR $node_url
ENV NODE_KEY $node_secret
ENV LOG_LEVEL WARNING

# copy all code
COPY . ./

# Run the web service on container startup. Here we use the gunicorn
# webserver, with one worker process and 8 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
CMD exec gunicorn --bind :$PORT --workers 1 --threads 1 --timeout 0 blockchat.app:app
