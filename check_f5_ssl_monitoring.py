#!/usr/bin/env python3
import os
import logging
import sys
from datetime import datetime

import jsonargparse
from f5.bigip import ManagementRoot

NOW = datetime.now()
CRITICAL = []
WARNING = []
TO_DELETE = []

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)


def verify_cert(cert, warning, critical):
    logging.debug("[x] Verifying {}".format(cert.name))
    expiration_time = datetime.fromtimestamp(cert.expirationDate)

    delta = expiration_time - NOW
    if delta.days >= 0 and delta.days <= critical:
        logging.critical("{} is in less than {} days".format(expiration_time, critical))
        CRITICAL.append(cert)
        logging.critical(
            "Certificate {} is going to expire in {} days".format(cert.name, delta.days)
        )
    elif delta.days >= 0 and delta.days <= warning:
        logging.critical("{} is in less than {} days".format(expiration_time, warning))
        WARNING.append(cert)
        logging.critical(
            "Certificate {} is going to expire in {} days".format(cert.name, delta.days)
        )
    elif delta.days <= 0:
        logging.warning(
            "Certificate {} that expired {} days ago needs to be deleted".format(
                cert.name, delta.days
            )
        )
    logging.debug(" [-] Done.")


def check(args):
    logging.debug("[x] Connecting to F5..")
    mgmt = ManagementRoot(args.f5.ip, args.f5.user, args.f5.password)
    logging.debug(" [-] Connected.")
    logging.debug("[x] Fetching all certificates..")
    certs = mgmt.tm.sys.file.ssl_certs.get_collection()
    logging.debug(" [-] Done.")

    logging.debug("[x] Processing expiration time..")
    for cert in certs:
        verify_cert(cert, args.warning, args.critical)

    output = ""
    alert = False
    if len(CRITICAL):
        alert = True
        output += "CRITICAL: {} certificates are going to expire.".format(
            len(CRITICAL) + len(WARNING)
        )
    elif len(WARNING):
        alert = True
        output += "WARNING: {} certificates are going to expire.".format(len(WARNING))

    if alert:
        output += " Following certificates are raising the threshold: {}".format(
            ", ".join(
                [
                    "{} ({})".format(
                        x.name, datetime.fromtimestamp(int(x.expirationDate))
                    )
                    for x in WARNING + CRITICAL
                ]
            )
        )

    if not len(WARNING) and not len(CRITICAL):
        print("OK")
        sys.exit(0)

    print(output)
    if len(CRITICAL):
        sys.exit(2)
    sys.exit(1)


def main():
    parser = jsonargparse.ArgumentParser(
        description="Monitor SSL certificates expiration registered in a F5 server.",
        default_env=True,
    )
    parser.add_argument(
        "-w",
        "--warning",
        help="number of days to raise a warning",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-c",
        "--critical",
        help="number of days to raise a critical",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--f5.ip", help="F5 IP or hostname to connect to", required=True
    )
    parser.add_argument("--f5.user", help="F5 user to access Big IP API", required=True)
    parser.add_argument(
        "--f5.password", help="F5 password to access Big IP API", required=True
    )
    args = parser.parse_args()

    return check(args)


if __name__ == "__main__":
    main()
