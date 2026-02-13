import os
from flask import request

cmd = request.args.get("cmd")
os.system(cmd)

password = "supersecret"