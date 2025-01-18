# Use an official Python runtime as a parent image
FROM python:3.10

# Set the working directory inside the container
WORKDIR /app

# Copy the Python script into the container
COPY packet_capture.py /app/

# Create a /logs folder for storing logs
RUN mkdir /logs

# Install required dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install required Python libraries
RUN pip install scapy

# Expose the logs folder for external access (optional)
VOLUME ["/logs"]

# Run the script
CMD ["python", "packet_capture.py"]
