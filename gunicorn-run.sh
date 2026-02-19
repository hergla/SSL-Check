#!/usr/bin/sh

gunicorn --workers 3 \
         --bind 0.0.0.0:5000 \
         --certfile /etc/olbcert/fullchain.pem \
         --keyfile /etc/olbcert/server.key \
         --access-logfile /var/log/ssl-checker/ssl-inspector-access.log \
         --error-logfile /var/log/ssl-checker/ssl-inspector-error.log \
	 --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"' \
         ssl-check-web:app

