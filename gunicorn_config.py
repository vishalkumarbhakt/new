import multiprocessing

bind = "unix:/run/customer-api.sock"
workers = multiprocessing.cpu_count() * 2 + 1
timeout = 120
accesslog = "/home/s2cartofficial_gmail_com/Customer-API/logs/gunicorn.access.log"
errorlog = "/home/s2cartofficial_gmail_com/Customer-API/logs/gunicorn.error.log"
capture_output = True
loglevel = "info"
