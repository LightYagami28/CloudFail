# Use an official Debian image as a base
FROM debian:sid

# Set environment variables
ENV LANG=C.UTF-8
ENV USER=root
ENV HOME=/cloudfail
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install dependencies
RUN apt-get update && apt-get install -yq python3-pip

# Copy the current directory contents into the container at $HOME
COPY . $HOME

# Set the working directory to $HOME
WORKDIR $HOME

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Set the entrypoint to run the cloudfail.py script
ENTRYPOINT ["python3", "cloudfail.py"]
