FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY adblock ./adblock
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 53/udp 53/tcp 8080/tcp
CMD ["python", "-m", "adblock"]
