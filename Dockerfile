FROM python:2.7

ADD dist/ /dist
RUN pip install --no-cache-dir dist/*.whl

WORKDIR /rproxy
ENTRYPOINT ["python", "-m", "twisted", "--log-format=text"]
CMD ["rproxy"]

