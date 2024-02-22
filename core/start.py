import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import time
import core.global_state as global_state
import core.common
import core.config
import core.model
import core.networking
import core.arp_scanner
import core.arp_spoofer
import core.packet_collector
import core.packet_processor
import core.friendly_organizer
import core.data_donation
import os


def start_threads():

    logging.basicConfig(filename=os.path.join(core.common.get_project_directory(), 'inspector.log'), level=logging.INFO)

    with global_state.global_state_lock:
        if global_state.inspector_started[0]:
            logging.error('Another instance of Inspector is already running. Aborted.')
            return
        global_state.inspector_started[0] = True
        global_state.inspector_started_ts = time.time()

    logging.info('Starting Inspector')

    # Initialize the database
    logging.info('Initializing the database')
    core.model.initialize_tables()

    # Initialize the networking variables
    logging.info('Initializing the networking variables')
    core.networking.enable_ip_forwarding()
    core.networking.update_network_info()

    # Start various threads
    core.common.SafeLoopThread(core.arp_scanner.start_arp_scanner, sleep_time=5)
    core.common.SafeLoopThread(core.packet_collector.start_packet_collector, sleep_time=0)
    core.common.SafeLoopThread(core.packet_processor.process_packet, sleep_time=0)
    core.common.SafeLoopThread(core.arp_spoofer.spoof_internet_traffic, sleep_time=5)
    core.common.SafeLoopThread(core.friendly_organizer.add_hostname_info_to_flows, sleep_time=5)
    core.common.SafeLoopThread(core.friendly_organizer.add_product_info_to_devices, sleep_time=5)
    core.common.SafeLoopThread(core.data_donation.start, sleep_time=15)

    logging.info('Inspector started')



def clean_up():

    core.networking.disable_ip_forwarding()


def init():
    """
    Execute this function to start Inspector as a standalone application from the command line.

    """

    start_threads()

    # Loop until the user quits
    try:
        while True:
            time.sleep(1)
            with global_state.global_state_lock:
                if not global_state.is_running:
                    break

    except KeyboardInterrupt:
        pass

    clean_up()



