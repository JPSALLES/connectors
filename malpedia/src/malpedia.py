import os
import yaml
import time
import requests
import json
import re
import pytz
import stix2

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable


class Malpedia:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path))
            if os.path.isfile(config_file_path)
            else {}
        )
        self.interval = 1  # 1 Day interval between each scraping
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL", ["connector", "confidence_level"], config,
        )
        self.MALPEDIA_API = get_config_variable(
            "MALPEDIA_API", ["malpedia", "MALPEDIA_API"], config
        )
        self.AUTH_KEY = get_config_variable(
            "AUTH_KEY", ["malpedia", "AUTH_KEY"], config
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def run(self):
        self.helper.log_info("Fetching Malpedia datasets...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")

                    ## CORE ##

                    api_call = {
                        "API_CHECK_APIKEY": "check/apikey",
                        "API_GET_VERSION": "get/version",
                        "API_GET_FAMILIES": "get/families",
                        "API_LIST_ACTORS": "list/actors",
                        "API_GET_FAMILY": "get/family/",
                        "API_LIST_FAMILIES": "list/families",
                        "API_GET_YARA": "get/yara/",
                        'API_LIST_SAMPLES': 'list/samples/',
                    }

                    # API Key check
                    r = requests.get(
                        self.MALPEDIA_API + api_call["API_CHECK_APIKEY"],
                        headers={"Authorization": "apitoken " + self.AUTH_KEY},
                    )
                    response_json = r.json()
                    if "Valid token" in response_json["detail"]:
                        print("--- Authentication successful.")
                    else:
                        print("--- Authentication failed.")
                    # API Version check
                    r = requests.get(self.MALPEDIA_API + api_call["API_GET_VERSION"])
                    response_json = r.json()
                    print(
                        "--- Malpedia version: "
                        + str(response_json["version"])
                        + " ("
                        + response_json["date"]
                        + ")"
                    )
                    ###[TODO] Le check de la version : utiliser self.helper.set_state
                    # if malpedia_latest_check is None:
                    #    global malpedia_latest_check = response_json["version"]
                    # else:
                    #    if response_json["version"] > malpedia_latest_check:
                    # y mettre la suite
                    #    else:
                    #        print("----- Version " + str(response_json["version"]) + " already imported.")

                    ### MAIN GET ###
                    ###get list of families
                    r = requests.get(
                        self.MALPEDIA_API + api_call["API_LIST_FAMILIES"],
                        headers={"Authorization": "apitoken " + self.AUTH_KEY},
                    )
                    list_of_families_json = r.json()

                    ###get families
                    r = requests.get(
                        self.MALPEDIA_API + api_call["API_GET_FAMILIES"],
                        headers={"Authorization": "apitoken " + self.AUTH_KEY},
                    )
                    families_json = r.json()

                    ###get list of actors
                    r = requests.get(
                        self.MALPEDIA_API + api_call["API_LIST_ACTORS"],
                        headers={"Authorization": "apitoken " + self.AUTH_KEY},
                    )
                    list_actors_json = r.json()

                    # Get all marking definitions
                    marking_definitions = self.helper.api.marking_definition.list()

                    ### [TODO] y a pas de get/actors donc va falloir faire un appel pour chaque actor de la liste

                    ### WORK ###

                    # Link to malpedia website, to add in everything we create
                    external_reference_malpedia = self.helper.api.external_reference.create(
                        source_name="Malpedia ("
                        + str(response_json["version"])
                        + " ("
                        + response_json["date"]
                        + ")",
                        url="https://malpedia.caad.fkie.fraunhofer.de",
                    )

                    malpedia_organization = self.helper.api.identity.create(
                        type="Organization",
                        name="Malpedia",
                        description="Malpedia is a free service offered by Fraunhofer FKIE.",
                    )

                    # for family in families:
                    # print(json.dumps(list_of_families_json, indent=4, sort_keys=True))
                    print("[-] Begin import of malwares families")
                    for name in list_of_families_json:
                        # we create the malware(family)
                        malware = self.helper.api.malware.create(
                            name=families_json[name]["common_name"],
                            description=families_json[name]["description"],
                            createdByRef=malpedia_organization["id"],
                            markingDefinitions=['c4ae0c3a-3535-44e2-b206-bb451c25c749'],
                            alias=families_json[name]["alt_names"],
                        )
                        # we add main external reference to malpedia website
                        self.helper.api.stix_entity.add_external_reference(
                            id=malware["id"],
                            external_reference_id=external_reference_malpedia["id"],
                        )
                        # we could too add each url referenced in the malpedia entity
                        for ref in families_json[name]["urls"]:
                            ref_name = ref.split('/')[2]
                            ref = self.helper.api.external_reference.create(
                                source_name=ref_name,
                                url=ref,
                            )
                        #        filters=[{"key": "URL", "values": [ref]}]
                        #    if not ref_exist:
                        #        external_reference = opencti_api_client.external_reference.create(
                        #            source_name="Malpedia's sources", url=ref
                        #        )
                        #    )


                        # we add yara rules associated with the malware
                        r = requests.get(
                            self.MALPEDIA_API + api_call["API_GET_YARA"] + name,
                            headers={"Authorization": "apitoken " + self.AUTH_KEY},
                        )
                        list_yara = r.json()
                        for yara in list_yara:
                            for name_rule, rule in list_yara[yara].items():
                                # extract yara date
                                date = None
                                date = rule.split("malpedia_version = ")[1].split('\n')[0].replace('"', '').replace('-', '').strip()
                                if date is None:
                                    date = response_json["date"]
                                else:
                                    date = datetime.strptime(date, "%Y%m%d")
                                    date = datetime.strftime(date, "%Y-%m-%dT%H:%M:%SZ")
                                # extract tlp
                                tlp = rule.split("malpedia_sharing = ")[1].split('\n')[0].replace('"', '').strip()
                                for marking_definition in marking_definitions:
                                    if tlp == marking_definition["definition"]:
                                        tlp = marking_definition["id"]
                                # extract author
                                yara_author = rule.split("author = ")[1].split('\n')[0].replace('"', '').strip()
                                # add yara
                                indicator = self.helper.api.indicator.create(
                                    name=name_rule,
                                    description="[Malpedia] Yara from "+yara_author,
                                    pattern_type="yara",
                                    indicator_pattern=rule,
                                    main_observable_type="File-SHA256",
                                    valid_from=date,
                                    markingDefinitions=[tlp],
                                )
                                relation = self.helper.api.stix_relation.create(
                                    fromType="Indicator",
                                    fromId=indicator["id"],
                                    toType="Malware",
                                    toId=malware["id"],
                                    relationship_type="indicates",
                                    first_seen=date,
                                    last_seen=date,
                                    description="Yara rules for "
                                    + families_json[name]["common_name"]
                                    + ".",
                                    weight=self.confidence_level,
                                    role_played="Unknown",
                                    createdByRef=malpedia_organization["id"],
                                    markingDefinitions=[tlp],
                                    ignore_dates=True,
                                    update=True,
                                )

                        # we add samples associated with the malware
                        r = requests.get(
                            self.MALPEDIA_API + api_call["API_LIST_SAMPLES"] + name,
                            headers={"Authorization": "apitoken " + self.AUTH_KEY},
                        )
                        list_samples = r.json()
                        for sample in list_samples:
                            print("[----] Adding sample")
                            # we add the ample only if we find a date
                            if sample["version"] != '':
                                date = re.search(r'\d{4}-\d{2}-\d{2}', sample["version"])
                                # if version field doesn't contained date, we do not add the sample
                                if date is not None:
                                    date = date.group()
                                    date = datetime.strptime(date, "%Y-%m-%d")
                                    date = datetime.strftime(date, "%Y-%m-%dT%H:%M:%SZ")
                                    indicator = self.helper.api.indicator.create(
                                        name=sample["sha256"],
                                        description="[Malpedia] Sample version : " + sample["version"],
                                        pattern_type="file",
                                        indicator_pattern=sample["sha256"],
                                        main_observable_type="File-SHA256",
                                        valid_from=date,
                                        markingDefinitions=['c4ae0c3a-3535-44e2-b206-bb451c25c749'],
                                    )
                                    relation = self.helper.api.stix_relation.create(
                                        fromType="Indicator",
                                        fromId=indicator["id"],
                                        toType="Malware",
                                        toId=malware["id"],
                                        relationship_type="indicates",
                                        first_seen=date,
                                        last_seen=date,
                                        description="[Malpedia] Sample version : " + sample["version"] + ".",
                                        weight=self.confidence_level,
                                        role_played="Unknown",
                                        createdByRef=malpedia_organization["id"],
                                        markingDefinitions=['c4ae0c3a-3535-44e2-b206-bb451c25c749'],
                                        ignore_dates=True,
                                        update=True,
                                    )

                        # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        malpediaConnector = Malpedia()
        malpediaConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
