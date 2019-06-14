import argparse
from manager import *


def main():
	# instanzio un oggetto parser
    parser = init_parser()
	# effettuo il parsing degli argomenti
    args = parser.parse_args()
    # instanzio un oggetto manager per la gestione dei vari thread
    manager = Manager(
        interface=args.interface,
        ip_app_files=args.files,
        addresses_hosts=args.addressesHost,
        ip_gateway=args.gateway
    )
    # avvio il manager
    manager.run_manager()


def init_parser():
    """
    :return parser: oggetto delegato al parsing degli argomenti del programma
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', help=config.DESCR_INTERFACE, required=True)
    parser.add_argument('-f', '--files', nargs='+', help=config.DESCR_FILES, required=True)
    parser.add_argument('-ah', '--addressesHost', nargs='*', help=config.DESCR_ADDRESSES_HOST)
    parser.add_argument('-g', '--gateway', help=config.DESCR_GATEWAY)
    return parser


if __name__ == "__main__":
    main()
