import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
# SQLite allows one writer at a time; PostgreSQL deployments can raise WEB_CONCURRENCY.
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
timeout = 60
accesslog = "-"
errorlog = "-"
# Do not log query strings: search terms can themselves be sensitive.
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(B)s %(L)ss rid=%({x-request-id}o)s'
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
limit_request_line = 4094
