from functools import lru_cache
import json
import numpy as np

# clean the code. 

with open('Capture-mixed-7.profiles.json') as data_file:
    data_7 = json.load(data_file)


with open('Capture-mixed-8.profiles.json') as data_file:
    data_8 = json.load(data_file)

with open('capture-WinFull-1.profiles.json') as data_file:
    normal_data_win_full = json.load(data_file)
    
with open('CTU-Mixed-2018-04-04_mixed.profiles.json') as data_file:
    anomalous_data_win_full = json.load(data_file)

with open('CTU-Mixed-7.profiles.json') as data_file:
    anomalous_data_mixed_7 = json.load(data_file)


ip = '10.0.2.15'
global_features = [
    'clientDestinationPortTotalBytesUDPEstablished',
'clientDestinationPortNumberOfFlowsTCPEstablished',
'clientDestinationPortNumberOfFlowsUDPNotEstablished',
'clientDestinationPortTotalPacketsTCPEstablished',
'clientDestinationPortNumberOfFlowsUDPEstablished',
'clientDestinationPortTotalPacketsTCPNotEstablished',
'clientDestinationPortTotalBytesUDPNotEstablished',
'clientDestinationPortTotalBytesTCPEstablished',
'clientDestinationPortTotalPacketsUDPNotEstablished',
'clientDestinationPortNumberOfFlowsTCPNotEstablished',
'clientDestinationPortTotalBytesTCPNotEstablished',
'clientDestinationPortTotalPacketsUDPEstablished']


def create_features(histogram):
    backet_size = 100
    keys_range_1 = range(0,1001)
    keys_range_2 = range(1001,65535, backet_size)
    
    features_func = []
    for key in keys_range_1:
        features_func.append(histogram.get(str(key), 0))

    for key in keys_range_2:
        total = 0
        ports_in_range = set(range(key,key+backet_size))
        features_func.append(0)
        for port in ports_in_range:
            if str(port) in histogram:
                features_func[-1]+=histogram[str(port)]
                total+=1
        if total>0:
            features_func[-1] /= total
    return features_func


@lru_cache(maxsize=32)
def get_normal_data(feature_name, dataset=1):
    baseline = {}
    
    if dataset == 1:
        prof_7 = data_7[ip]['time']
        prof_8 = data_8[ip]['time']
        baseline = {k:v for (k,v) in prof_7.items() if ('-17' in k) | ('18' in k)}
        baseline['2017-08-22'] = {k:v for (k,v) in prof_7['2017-08-22'].items() if ('09 ' in k) | ('10 ' in k)}
        del baseline['2017-08-22']['10 11']
        del baseline['2017-08-22']['10 10']
        del baseline['2017-08-22']['10 9']
        baseline['2017-08-24'] = {k:v for (k,v) in prof_8['2017-08-24'].items() if ('15' in k) | ('14' in k) | ('16' in k)}
    elif dataset==2:
        profiles = normal_data_win_full[ip]['time']
        baseline = {k:v for (k,v) in profiles.items()} 
         
    return baseline

@lru_cache(maxsize=32)
def get_anomaly_data(feature_name, dataset=1):
    if dataset==1:
        prof_8 = data_8[ip]['time']
        anomaly_profiles = [prof_8['2017-08-24'][key][feature_name] for key in prof_8['2017-08-24'].keys() if ('17' in key) | ('18' in key)| ('19' in key)]
    elif dataset == 2:
        profiles = anomalous_data_win_full[ip]['time']
        anomaly_profiles = [profiles['1970/01/01'][key][feature_name] for key in profiles['1970/01/01'].keys()]
    elif dataset == 3:
        profiles = anomalous_data_mixed_7[ip]['time']
        anomaly_profiles = [profiles['1970/01/01'][key][feature_name] for key in profiles['1970/01/01'].keys()]
        
        
    return anomaly_profiles

@lru_cache(maxsize=32)
def generate_normal_features(feature_name, dataset=1):
    baseline = get_normal_data(feature_name,dataset=dataset)
    features = []
    labels = []
    for date in baseline.keys():
        day_profile = baseline[date]
        for time in day_profile.keys():
            histogram = day_profile[time][feature_name]
            labels.append(date+' '+time)
            features.append(create_features(histogram))
    return np.array(features)

@lru_cache(maxsize=32)
def generate_anomaly_features(feature_name,dataset=1):
    anomaly_features = []
    anomaly_profiles = get_anomaly_data(feature_name,dataset=dataset)
    for hist in anomaly_profiles:
        anomaly_features.append(create_features(hist))
    return np.array(anomaly_features)

def select_threshold(X_train_dst_local):
    min_val = X_train_dst_local.min()

def get_evaluation_matrix(labels, predicted, benign_range, anomaly_range):
    true_positive = np.sum(predicted[anomaly_range] == labels[anomaly_range])
    false_positive = np.sum(predicted[benign_range] != labels[benign_range])
    true_negative = np.sum(predicted[benign_range] == labels[benign_range])
    false_negative = np.sum(predicted[anomaly_range] != labels[anomaly_range])
    return true_positive, false_positive, true_negative, false_negative

def compute_precision_recall_accuracy(true_positive, false_positive, true_negative, false_negative):
    precision = true_positive/(true_positive + false_positive)
    recall = true_positive/(true_positive + false_negative)
    accuracy = (true_positive+true_negative)/(true_positive+true_negative+false_negative+false_positive)
    return precision, recall, accuracy

def print_evaluation(precision, recall, accuracy, feature_name):
    print('===========================================================')
    print('Feature name: {}'.format(feature_name))
    print('tp=',true_positive, 'tn=',true_negative,'fp=',false_positive,'fn=',false_negative)
    print('False positive rate: ', false_positive/(false_positive+true_negative))

    print('False negative: ', 1-false_positive/(false_positive+true_negative))
    print('\n')
    print('Precision: ', precision)
    print('Recall: ', recall)
    print('Accuracy: ', accuracy)
