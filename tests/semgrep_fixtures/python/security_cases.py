"""Fixture for the Python security rules — see `quality_cases.py` for the marker format.

Every rule here is paired with a *near miss* on the following lines: the literal command,
the safe loader, the hash declared as non-security. Those are what stop a rule from being
a nuisance, and a rule that starts flagging them would be discovered by users rather than
by the suite.
"""
import hashlib
import os
import pickle
import random
import ssl
import subprocess

import httpx
import jinja2
import requests
import yaml


def command_execution(user_input, app):
    subprocess.run(user_input, shell=True)  # zanshin: zanshin-python-subprocess-shell-true
    subprocess.run("ls -l", shell=True)
    subprocess.run(["ls", "-l"])
    os.system(user_input)  # zanshin: zanshin-python-os-system
    os.system("ls")
    eval(user_input)  # zanshin: zanshin-python-eval-exec
    eval("1 + 1")
    exec(user_input)  # zanshin: zanshin-python-eval-exec


def deserialization(document, blob):
    yaml.load(document)  # zanshin: zanshin-python-yaml-unsafe-load
    yaml.load(document, Loader=yaml.FullLoader)  # zanshin: zanshin-python-yaml-unsafe-load
    yaml.safe_load(document)
    pickle.loads(blob)  # zanshin: zanshin-python-pickle-load


def hashing(payload):
    hashlib.md5(payload)  # zanshin: zanshin-python-weak-hash
    hashlib.sha1(payload)  # zanshin: zanshin-python-weak-hash
    hashlib.md5(payload, usedforsecurity=False)
    hashlib.sha256(payload)


def transport():
    requests.get("https://example.test", verify=False)  # zanshin: zanshin-python-requests-verify-false
    httpx.Client(verify=False)  # zanshin: zanshin-python-requests-verify-false
    requests.get("https://example.test")
    ssl._create_unverified_context()  # zanshin: zanshin-python-ssl-unverified-context
    ssl.create_default_context()


def secrets_and_timing(supplied):
    token = random.randint(0, 10**9)  # zanshin: zanshin-python-insecure-random-secret
    backoff = random.random()
    if token == supplied:  # zanshin: zanshin-python-password-timing-comparison
        return backoff
    if backoff == supplied:
        return None
    return token


def templating():
    jinja2.Environment()  # zanshin: zanshin-python-jinja-autoescape-off
    jinja2.Environment(autoescape=True)


def serve(app):
    app.run(debug=True)  # zanshin: zanshin-python-flask-debug
    app.run(debug=False)
