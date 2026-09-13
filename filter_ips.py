#!/usr/bin/env python3

import os
import ipaddress
import logging
from pathlib import Path

import pandas as pd
import requests
import SubnetTree
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

GEOIP_CSV_PATH = os.getenv(
    "GEOIP_CSV_PATH",
    "/data/geoip/geoip2-ipv4.csv"
)

INPUT_FILE = os.getenv(
    "ALL_IPS_FROM_LISTS",
    "/data/output/aggregated.txt"
)

OUTPUT_FILE = os.getenv(
    "FILTERED_OUTPUT",
    "/data/output/aggregated-vyos.txt"
)

EXCLUDE_COUNTRIES = {
    x.strip().upper()
    for x in os.getenv(
        "EXCLUDE_COUNTRIES",
        "RU,CN,KP,IR,BY"
    ).split(",")
    if x.strip()
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


# ---------------------------------------------------------------------------
# GeoIP database
# ---------------------------------------------------------------------------

def download_geoip_file():
    """Download the GeoIP database if it does not already exist."""

    if os.path.exists(GEOIP_CSV_PATH):
        logging.info(
            "GeoIP database already exists: %s",
            GEOIP_CSV_PATH
        )
        return

    url = "https://datahub.io/core/geoip2-ipv4/r/geoip2-ipv4.csv"

    logging.info("Downloading GeoIP database...")

    Path(GEOIP_CSV_PATH).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    response = requests.get(
        url,
        timeout=120
    )

    response.raise_for_status()

    with open(GEOIP_CSV_PATH, "wb") as f:
        f.write(response.content)

    logging.info("GeoIP database downloaded.")


# ---------------------------------------------------------------------------
# Build exclusion tree
# ---------------------------------------------------------------------------

def build_exclusion_tree():
    """
    Build a SubnetTree containing all networks belonging to
    EXCLUDE_COUNTRIES.
    """

    logging.info(
        "Loading GeoIP database: %s",
        GEOIP_CSV_PATH
    )

    df = pd.read_csv(GEOIP_CSV_PATH)

    required_columns = {
        "network",
        "country_iso_code"
    }

    missing = required_columns - set(df.columns)

    if missing:
        raise RuntimeError(
            f"GeoIP database is missing columns: {missing}"
        )

    # Normalize country codes.
    df["country_iso_code"] = (
        df["country_iso_code"]
        .fillna("")
        .astype(str)
        .str.upper()
        .str.strip()
    )

    excluded = df[
        df["country_iso_code"].isin(EXCLUDE_COUNTRIES)
    ]

    logging.info(
        "GeoIP networks belonging to excluded countries: %d",
        len(excluded)
    )

    tree = SubnetTree.SubnetTree()

    added = 0

    for network in excluded["network"].dropna():

        try:
            tree[str(network)] = True
            added += 1

        except Exception as exc:
            logging.warning(
                "Could not add GeoIP network %s: %s",
                network,
                exc
            )

    logging.info(
        "Added %d GeoIP networks to exclusion tree.",
        added
    )

    return tree


# ---------------------------------------------------------------------------
# IP lookup
# ---------------------------------------------------------------------------

def is_excluded(network_string, exclusion_tree):
    """
    Return True when the IP/network belongs to one of the excluded
    countries.

    For CIDRs, the network address is used for the GeoIP lookup.
    """

    try:

        if "/" in network_string:

            network = ipaddress.ip_network(
                network_string,
                strict=False
            )

            address = str(network.network_address)

        else:

            address = str(
                ipaddress.ip_address(network_string)
            )

        return address in exclusion_tree

    except ValueError:

        logging.debug(
            "Invalid IP/network: %s",
            network_string
        )

        return False


def is_private_or_reserved(network_string):
    """
    Return True for RFC1918 / loopback / link-local / other
    non-routable ranges (e.g. 10.0.0.0/8, 172.16.0.0/12,
    192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, CGNAT, etc.) that
    should never appear in a perimeter blocklist -- some public
    threat-intel feeds (FireHOL Level1 among them) intentionally
    include a few of these as "bogon" entries, which is fine for a
    pure internet-facing drop list but dangerous if this list is ever
    referenced by a rule that also sees internal/VPN traffic.
    """

    try:

        if "/" in network_string:

            network = ipaddress.ip_network(
                network_string,
                strict=False
            )

        else:

            network = ipaddress.ip_network(
                f"{network_string}/32",
                strict=False
            )

        return network.is_private

    except ValueError:

        logging.debug(
            "Invalid IP/network: %s",
            network_string
        )

        return False


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def filter_blocklist(exclusion_tree):

    logging.info(
        "Reading aggregated input: %s",
        INPUT_FILE
    )

    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"Input file does not exist: {INPUT_FILE}"
        )

    Path(OUTPUT_FILE).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    total = 0
    kept = 0
    excluded = 0
    private = 0
    invalid = 0

    # Write to a temporary file first.
    temp_file = OUTPUT_FILE + ".tmp"

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as source, open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as destination:

        for line in source:

            value = line.strip()

            if not value:
                continue

            total += 1

            try:

                if is_private_or_reserved(value):

                    private += 1

                elif is_excluded(
                    value,
                    exclusion_tree
                ):

                    excluded += 1

                else:

                    destination.write(
                        value + "\n"
                    )

                    kept += 1

            except Exception:

                invalid += 1

                logging.debug(
                    "Failed to process: %s",
                    value
                )

            if total % 100000 == 0:

                logging.info(
                    "Processed %s entries "
                    "(kept %s / excluded %s / private %s)",
                    f"{total:,}",
                    f"{kept:,}",
                    f"{excluded:,}",
                    f"{private:,}"
                )

    os.replace(
        temp_file,
        OUTPUT_FILE
    )

    logging.info("")
    logging.info("========================================")
    logging.info("GeoIP filtering complete")
    logging.info("========================================")
    logging.info("Input:              %s", f"{total:,}")
    logging.info("Excluded (GeoIP):   %s", f"{excluded:,}")
    logging.info("Private/reserved:   %s", f"{private:,}")
    logging.info("Remaining:          %s", f"{kept:,}")
    logging.info("Invalid/skipped:    %s", f"{invalid:,}")
    logging.info("Excluded countries: %s",
                 ",".join(sorted(EXCLUDE_COUNTRIES)))
    logging.info("Output:             %s", OUTPUT_FILE)
    logging.info("========================================")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    logging.info(
        "Starting VyOS blacklist GeoIP filter"
    )

    logging.info(
        "Excluded countries: %s",
        ", ".join(sorted(EXCLUDE_COUNTRIES))
    )

    download_geoip_file()

    exclusion_tree = build_exclusion_tree()

    filter_blocklist(
        exclusion_tree
    )


if __name__ == "__main__":
    main()
