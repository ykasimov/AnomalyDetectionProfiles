import argparse

parser_data_gathering = argparse.ArgumentParser(description='Anomaly detection parameter parser')
parser_data_gathering.add_argument('-ip', nargs='*', help='list of IPs to search', required=True)
parser_data_gathering.add_argument('-save_to', dest='file', required=True)
parser_data_gathering.add_argument('-train', dest='train_file', required=True)

parser_training = argparse.ArgumentParser(description='Anomaly detection parameter parser')
parser_training.add_argument('-normal', dest='normal_data', required=True)
parser_training.add_argument('-valid', dest='validation_data', required=True)
parser_training.add_argument('-algorithm', dest='algorithm', default='OCSVM', choices=['OCSVM', 'LOF'])
parser_training.add_argument('-save', dest='models_path', default='models')
parser_training.add_argument('-params', dest='params')


parser_inference = argparse.ArgumentParser(description='Anomaly detection inference parser')
parser_inference.add_argument('-models', dest='models', required=True)
parser_inference.add_argument('-profiles', dest='profiles', required=True)
parser_inference.add_argument('-verbose', action='store_true', default=False)


