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

# Existing aggregated output from the main aggregator.
INPUT_FILE = os.getenv(
    "ALL_IPS_FROM_LISTS",
    "/data/output/aggregated.txt"
)

# Additional Blocklist.de source.
BLOCKLIST_DE_URL = os.getenv(
    "BLOCKLIST_DE_URL",
    "https://lists.blocklist.de/lists/all.txt"
)

BLOCKLIST_DE_FILE = os.getenv(
    "BLOCKLIST_DE_FILE",
    "/data/input/blocklist-de-all.txt"
)

# IPv4 GeoIP database.
GEOIP_IPV4_CSV_PATH = os.getenv(
    "GEOIP_CSV_PATH",
    "/data/geoip/geoip2-ipv4.csv"
)

# Optional IPv6 GeoIP database.
#
# This must be a MaxMind-style GeoLite2 Country IPv6 CSV containing:
#   network
#   geoname_id / registered_country_geoname_id
#
# Country mapping is handled separately below.
GEOIP_IPV6_CSV_PATH = os.getenv(
    "GEOIP_IPV6_CSV_PATH",
    "/data/geoip/GeoLite2-Country-Blocks-IPv6.csv"
)

# Final outputs.
OUTPUT_IPV4_FILE = os.getenv(
    "FILTERED_OUTPUT",
    "/data/output/aggregated-vyos.txt"
)

OUTPUT_IPV6_FILE = os.getenv(
    "FILTERED_IPV6_OUTPUT",
    "/data/output/aggregated-vyos-ipv6.txt"
)

# Optional IPv6 country filtering.
#
# Set to "true" only if GEOIP_IPV6_CSV_PATH is present and usable.
ENABLE_IPV6_GEOIP = os.getenv(
    "ENABLE_IPV6_GEOIP",
    "false"
).lower() in ("1", "true", "yes", "on")

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
# Download helper
# ---------------------------------------------------------------------------

def download_file(url, destination):
    """Download a URL to a local file atomically."""

    destination = Path(destination)

    destination.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temp_file = destination.with_suffix(
        destination.suffix + ".tmp"
    )

    logging.info(
        "Downloading %s",
        url
    )

    response = requests.get(
        url,
        timeout=180,
        stream=True
    )

    response.raise_for_status()

    total_bytes = 0

    with open(temp_file, "wb") as f:

        for chunk in response.iter_content(
            chunk_size=1024 * 1024
        ):

            if chunk:

                f.write(chunk)
                total_bytes += len(chunk)

    os.replace(
        temp_file,
        destination
    )

    logging.info(
        "Downloaded %s (%.1f MB)",
        destination,
        total_bytes / 1024 / 1024
    )


# ---------------------------------------------------------------------------
# Blocklist.de
# ---------------------------------------------------------------------------

def download_blocklist_de():

    download_file(
        BLOCKLIST_DE_URL,
        BLOCKLIST_DE_FILE
    )


# ---------------------------------------------------------------------------
# GeoIP
# ---------------------------------------------------------------------------

def download_geoip_ipv4():
    """
    Download the existing DataHub IPv4 GeoIP database if necessary.
    """

    if os.path.exists(GEOIP_IPV4_CSV_PATH):

        logging.info(
            "IPv4 GeoIP database already exists: %s",
            GEOIP_IPV4_CSV_PATH
        )

        return

    url = (
        "https://datahub.io/core/geoip2-ipv4/"
        "_r/-/data/geoip2-ipv4.csv"
    )

    logging.info(
        "Downloading IPv4 GeoIP database..."
    )

    download_file(
        url,
        GEOIP_IPV4_CSV_PATH
    )


# ---------------------------------------------------------------------------
# Build IPv4 exclusion tree
# ---------------------------------------------------------------------------

def build_ipv4_exclusion_tree():

    logging.info(
        "Loading IPv4 GeoIP database: %s",
        GEOIP_IPV4_CSV_PATH
    )

    df = pd.read_csv(
        GEOIP_IPV4_CSV_PATH
    )

    required_columns = {
        "network",
        "country_iso_code"
    }

    missing = required_columns - set(
        df.columns
    )

    if missing:

        raise RuntimeError(
            f"IPv4 GeoIP database is missing columns: {missing}"
        )

    df["country_iso_code"] = (
        df["country_iso_code"]
        .fillna("")
        .astype(str)
        .str.upper()
        .str.strip()
    )

    excluded = df[
        df["country_iso_code"].isin(
            EXCLUDE_COUNTRIES
        )
    ]

    logging.info(
        "IPv4 GeoIP networks belonging to excluded "
        "countries: %d",
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
                "Could not add IPv4 GeoIP network %s: %s",
                network,
                exc
            )

    logging.info(
        "Added %d IPv4 GeoIP networks to exclusion tree.",
        added
    )

    return tree


# ---------------------------------------------------------------------------
# Optional IPv6 GeoIP exclusion
# ---------------------------------------------------------------------------

def build_ipv6_exclusion_tree():

    if not ENABLE_IPV6_GEOIP:

        logging.info(
            "IPv6 GeoIP filtering is disabled."
        )

        return None

    if not os.path.exists(
        GEOIP_IPV6_CSV_PATH
    ):

        logging.warning(
            "IPv6 GeoIP database not found: %s",
            GEOIP_IPV6_CSV_PATH
        )

        logging.warning(
            "IPv6 country exclusion will NOT be applied."
        )

        return None

    logging.info(
        "Loading IPv6 GeoIP database: %s",
        GEOIP_IPV6_CSV_PATH
    )

    df = pd.read_csv(
        GEOIP_IPV6_CSV_PATH
    )

    if "network" not in df.columns:

        raise RuntimeError(
            "IPv6 GeoIP database does not contain "
            "'network' column."
        )

    # MaxMind Blocks-IPv6.csv uses geoname_id /
    # registered_country_geoname_id rather than the
    # country_iso_code column used by the DataHub dataset.
    #
    # Therefore, country filtering requires a separate
    # locations CSV. We deliberately do not guess here.
    if "country_iso_code" not in df.columns:

        logging.warning(
            "IPv6 GeoIP CSV does not contain "
            "'country_iso_code'."
        )

        logging.warning(
            "IPv6 country filtering is therefore disabled "
            "until an IPv6 CSV with country_iso_code is supplied."
        )

        return None

    df["country_iso_code"] = (
        df["country_iso_code"]
        .fillna("")
        .astype(str)
        .str.upper()
        .str.strip()
    )

    excluded = df[
        df["country_iso_code"].isin(
            EXCLUDE_COUNTRIES
        )
    ]

    tree = SubnetTree.SubnetTree()

    added = 0

    for network in excluded["network"].dropna():

        try:

            tree[str(network)] = True
            added += 1

        except Exception as exc:

            logging.warning(
                "Could not add IPv6 GeoIP network %s: %s",
                network,
                exc
            )

    logging.info(
        "Added %d IPv6 GeoIP networks to exclusion tree.",
        added
    )

    return tree


# ---------------------------------------------------------------------------
# IP parsing
# ---------------------------------------------------------------------------

def parse_network(value):

    value = value.strip()

    if not value:

        raise ValueError(
            "Empty address"
        )

    return ipaddress.ip_network(
        value,
        strict=False
    )


def is_private_or_reserved(value):

    try:

        network = parse_network(
            value
        )

        return (
            network.is_private
            or network.is_loopback
            or network.is_link_local
            or network.is_reserved
            or network.is_unspecified
            or network.is_multicast
        )

    except ValueError:

        return False


# ---------------------------------------------------------------------------
# GeoIP lookup
# ---------------------------------------------------------------------------

def is_excluded(
    value,
    exclusion_tree
):

    if exclusion_tree is None:

        return False

    try:

        network = parse_network(
            value
        )

        # Use the first/network address for the lookup.
        address = str(
            network.network_address
        )

        return address in exclusion_tree

    except ValueError:

        return False


# ---------------------------------------------------------------------------
# Read Blocklist.de
# ---------------------------------------------------------------------------

def read_blocklist_de():

    logging.info(
        "Reading Blocklist.de: %s",
        BLOCKLIST_DE_FILE
    )

    if not os.path.exists(
        BLOCKLIST_DE_FILE
    ):

        raise FileNotFoundError(
            f"Blocklist.de file does not exist: "
            f"{BLOCKLIST_DE_FILE}"
        )

    return open(
        BLOCKLIST_DE_FILE,
        "r",
        encoding="utf-8",
        errors="ignore"
    )


# ---------------------------------------------------------------------------
# Filtering + family separation
# ---------------------------------------------------------------------------

def collect_addresses(
    ipv4_tree,
    ipv6_tree
):

    logging.info(
        "Processing blacklist sources..."
    )

    if not os.path.exists(
        INPUT_FILE
    ):

        raise FileNotFoundError(
            f"Input file does not exist: {INPUT_FILE}"
        )

    ipv4_networks = []
    ipv6_networks = []

    statistics = {
        "input": 0,
        "blocklist_de": 0,
        "ipv4": 0,
        "ipv6": 0,
        "excluded_ipv4": 0,
        "excluded_ipv6": 0,
        "private": 0,
        "invalid": 0,
    }

    # -----------------------------------------------------------------------
    # Main aggregated input
    # -----------------------------------------------------------------------

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as source:

        for line in source:

            process_line(
                line,
                ipv4_tree,
                ipv6_tree,
                ipv4_networks,
                ipv6_networks,
                statistics
            )

    # -----------------------------------------------------------------------
    # Blocklist.de
    # -----------------------------------------------------------------------

    with read_blocklist_de() as source:

        for line in source:

            statistics["blocklist_de"] += 1

            process_line(
                line,
                ipv4_tree,
                ipv6_tree,
                ipv4_networks,
                ipv6_networks,
                statistics
            )

    return (
        ipv4_networks,
        ipv6_networks,
        statistics
    )


def process_line(
    line,
    ipv4_tree,
    ipv6_tree,
    ipv4_networks,
    ipv6_networks,
    statistics
):

    value = line.strip()

    if not value:

        return

    # Ignore comments.
    if value.startswith("#"):

        return

    statistics["input"] += 1

    try:

        network = parse_network(
            value
        )

    except ValueError:

        statistics["invalid"] += 1

        return

    # ---------------------------------------------------------------
    # Remove private / reserved / special-purpose networks.
    # ---------------------------------------------------------------

    if (
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_reserved
        or network.is_unspecified
        or network.is_multicast
    ):

        statistics["private"] += 1

        return

    # ---------------------------------------------------------------
    # IPv4
    # ---------------------------------------------------------------

    if network.version == 4:

        statistics["ipv4"] += 1

        if is_excluded(
            value,
            ipv4_tree
        ):

            statistics["excluded_ipv4"] += 1

            return

        ipv4_networks.append(
            network
        )

        return

    # ---------------------------------------------------------------
    # IPv6
    # ---------------------------------------------------------------

    if network.version == 6:

        statistics["ipv6"] += 1

        if is_excluded(
            value,
            ipv6_tree
        ):

            statistics["excluded_ipv6"] += 1

            return

        ipv6_networks.append(
            network
        )

        return


# ---------------------------------------------------------------------------
# CIDR aggregation
# ---------------------------------------------------------------------------

def collapse_networks(
    networks,
    family
):

    logging.info(
        "Collapsing IPv%d networks...",
        family
    )

    if not networks:

        return []

    collapsed = list(
        ipaddress.collapse_addresses(
            networks
        )
    )

    logging.info(
        "IPv%d before collapse: %s",
        family,
        f"{len(networks):,}"
    )

    logging.info(
        "IPv%d after collapse:  %s",
        family,
        f"{len(collapsed):,}"
    )

    return collapsed


# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------

def write_networks(
    networks,
    output_file
):

    output_file = Path(
        output_file
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temp_file = Path(
        str(output_file) + ".tmp"
    )

    # Sort by address/family/prefix for deterministic output.
    networks = sorted(
        networks,
        key=lambda n: (
            int(n.network_address),
            n.prefixlen
        )
    )

    with open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as destination:

        for network in networks:

            destination.write(
                str(network) + "\n"
            )

    os.replace(
        temp_file,
        output_file
    )

    size_mb = (
        output_file.stat().st_size
        / 1024
        / 1024
    )

    logging.info(
        "Output: %s",
        output_file
    )

    logging.info(
        "Entries: %s",
        f"{len(networks):,}"
    )

    logging.info(
        "Size: %.1f MB",
        size_mb
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    logging.info(
        "========================================"
    )

    logging.info(
        "Starting IPv4 + IPv6 VyOS blacklist filter"
    )

    logging.info(
        "========================================"
    )

    logging.info(
        "Excluded countries: %s",
        ", ".join(
            sorted(EXCLUDE_COUNTRIES)
        )
    )

    # ---------------------------------------------------------------
    # IPv4 GeoIP
    # ---------------------------------------------------------------

    download_geoip_ipv4()

    ipv4_tree = build_ipv4_exclusion_tree()

    # ---------------------------------------------------------------
    # IPv6 GeoIP
    # ---------------------------------------------------------------

    ipv6_tree = build_ipv6_exclusion_tree()

    # ---------------------------------------------------------------
    # Blocklist.de
    # ---------------------------------------------------------------

    download_blocklist_de()

    # ---------------------------------------------------------------
    # Collect
    # ---------------------------------------------------------------

    (
        ipv4_networks,
        ipv6_networks,
        statistics
    ) = collect_addresses(
        ipv4_tree,
        ipv6_tree
    )

    # ---------------------------------------------------------------
    # Collapse
    # ---------------------------------------------------------------

    ipv4_collapsed = collapse_networks(
        ipv4_networks,
        4
    )

    ipv6_collapsed = collapse_networks(
        ipv6_networks,
        6
    )

    # ---------------------------------------------------------------
    # Write
    # ---------------------------------------------------------------

    write_networks(
        ipv4_collapsed,
        OUTPUT_IPV4_FILE
    )

    write_networks(
        ipv6_collapsed,
        OUTPUT_IPV6_FILE
    )

    # ---------------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------------

    logging.info("")
    logging.info("========================================")
    logging.info("Filtering complete")
    logging.info("========================================")

    logging.info(
        "Input entries:       %s",
        f"{statistics['input']:,}"
    )

    logging.info(
        "Blocklist.de lines:  %s",
        f"{statistics['blocklist_de']:,}"
    )

    logging.info(
        "IPv4 input:          %s",
        f"{statistics['ipv4']:,}"
    )

    logging.info(
        "IPv6 input:          %s",
        f"{statistics['ipv6']:,}"
    )

    logging.info(
        "IPv4 GeoIP excluded: %s",
        f"{statistics['excluded_ipv4']:,}"
    )

    logging.info(
        "IPv6 GeoIP excluded: %s",
        f"{statistics['excluded_ipv6']:,}"
    )

    logging.info(
        "Private/reserved:    %s",
        f"{statistics['private']:,}"
    )

    logging.info(
        "Invalid/skipped:     %s",
        f"{statistics['invalid']:,}"
    )

    logging.info(
        "Final IPv4 entries:  %s",
        f"{len(ipv4_collapsed):,}"
    )

    logging.info(
        "Final IPv6 entries:  %s",
        f"{len(ipv6_collapsed):,}"
    )

    logging.info(
        "IPv4 output:         %s",
        OUTPUT_IPV4_FILE
    )

    logging.info(
        "IPv6 output:         %s",
        OUTPUT_IPV6_FILE
    )

    logging.info(
        "========================================"
    )


if __name__ == "__main__":
    main()
