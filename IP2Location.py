import requests
from math import cos, sqrt, radians
from datetime import datetime
import os
from dotenv import load_dotenv
import re

load_dotenv()
API_KEY = os.getenv('API_IP2L_KEY')
API_URL = os.getenv('API_IP2L_URL')
