import os
import json


IDPSS_CFGFILE = os.path.join(
    os.environ.get('HOME'),
    'idpss.conf')

cfg = {
    'bind_ip': '0.0.0.0',
    'port': 19988,
    'idp_env': os.path.join(
        os.environ.get('HOME'),
        ".idp.env"
    )
}

def load_cfg():
    try:
        with open(IDPSS_CFGFILE, "r") as f:
            cfg = json.load(f)
    except :
        pass

def save_cfg():
    try:
        with open(IDPSS_CFGFILE, "w") as f:
            json.dump(cfg, f)
    except :
        pass