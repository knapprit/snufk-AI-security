FROM python:3.9-slim
WORKDIR /app
RUN pip install kafka-python-ng
COPY brain.py .
CMD ["python", "brain.py"]