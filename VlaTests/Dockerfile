# Use the existing Python 2 image as the base
FROM opennetworking/ngsdn-tutorial:stratum_bmv2 AS base

# Create a new stage for Python 3
FROM python:3 AS python3

# Set the working directory
WORKDIR /root

# Copy the content from the base image into the Python 3 image
COPY --from=base / .

# Install virtualenv
RUN pip3 install virtualenv

# Create and activate a virtual environment
RUN python3 -m virtualenv venv && \
    . venv/bin/activate

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies from the requirements file
RUN pip install --no-cache-dir -r requirements.txt

# Specify an entry point or command for Python 3
#CMD ["python3", "your_python3_script.py"]
