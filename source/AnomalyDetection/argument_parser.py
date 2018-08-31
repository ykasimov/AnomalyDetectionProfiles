import argparse

parser_data_gathering = argparse.ArgumentParser(description='Anomaly detection parameter parser')
parser_data_gathering.add_argument('-ip', nargs='*', help='list of IPs to search', required=True)
parser_data_gathering.add_argument('-save_to', dest='file', required=True)
parser_data_gathering.add_argument('-train', dest='train_file', required=True)

parser_training = argparse.ArgumentParser(description='Anomaly detection parameter parser')
parser_training.add_argument('-normal', dest='normal_data', required=True)
parser_training.add_argument('-valid', dest='validation_data', required=True)
parser_training.add_argument('-algorithm', dest='algorithm', default='OCSVM', choices=['OCSVM', 'LOF'])


