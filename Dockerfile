# Use the official Python image as a base image
FROM python:3.13-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the domonitor_operator code into the container
COPY domonitor_operator/ /app/domonitor_operator/

# Set the entrypoint to run the operator
ENTRYPOINT ["kopf", "run", "--standalone", "--all-namespaces", "domonitor_operator/domonitor_operator.py"]
