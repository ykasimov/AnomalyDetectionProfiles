import json
import pickle
import numpy as np
from features import global_features


def create_features(histogram):
    backet_size = 100
    keys_range_1 = range(0, 1001)
    keys_range_2 = range(1001, 65535, backet_size)

    features_func = []
    for key in keys_range_1:
        features_func.append(histogram.get(str(key), 0))

    for key in keys_range_2:
        total = 0
        ports_in_range = set(range(key, key + backet_size))
        features_func.append(0)
        for port in ports_in_range:
            if str(port) in histogram:
                features_func[-1] += histogram[str(port)]
                total += 1
        if total > 0:
            features_func[-1] /= total
    return np.array(features_func)


def get_data(file, feature_names, data=None):
    def create_date(day, time_window):
        time_window_parts = time_window.split(' ')
        padding_zero = ''
        if len(time_window_parts[1]) < 2:
            padding_zero = '0'
        return (f'{day} {time_window_parts[0]}:'
                f'{padding_zero}'
                f'{int(time_window_parts[1])*5}:00')

    if not data:
        with open(file, 'r') as f:
            data = json.load(f)
    ip = list(data.keys())[0]
    profile = data[ip]['time']
    features_per_feature = {feat: [] for feat in feature_names}
    time_windows_dates = []
    for date, day_profile in profile.items():
        for time_window, histogram in day_profile.items():
            [features_per_feature[feat].append(create_features(histogram[feat])) for feat in feature_names]
            time_windows_dates.append(create_date(date, time_window))
    for feat in feature_names:
        features_per_feature[feat] = np.array(features_per_feature[feat])
    return features_per_feature, time_windows_dates


def get_evaluation_matrix(labels, predicted):
    anomaly_range = (labels == -1)
    benign_range = (labels == 1)
    true_positive = np.sum(predicted[anomaly_range] == labels[anomaly_range])
    false_positive = np.sum(predicted[benign_range] != labels[benign_range])
    true_negative = np.sum(predicted[benign_range] == labels[benign_range])
    false_negative = np.sum(predicted[anomaly_range] != labels[anomaly_range])
    return true_positive, false_positive, true_negative, false_negative


def majority_voting(predictions):
    """ text """
    majority_voting = sum(predictions)
    majority_voting[majority_voting > 0] = 1
    #
    majority_voting[majority_voting <= 0] = -1
    return majority_voting


def load_models(folder):
    models = {}
    for feature_name in global_features:
        path = f'{folder}/{feature_name}_model.pkl'
        with open(path, 'rb') as f:
            models[feature_name] = pickle.load(f).set_params(novelty=True)

    return models


def load_scalers(base_folder):
    folder = base_folder + '/scalers'
    scalers = {}
    for feature_name in global_features:
        path = f'{folder}/{feature_name}_scaler.pkl'
        with open(path, 'rb') as f:
            scalers[feature_name] = pickle.load(f)
    return scalers


def report(predictions, scores, dates):
    output_dict = {}
    for pred, score, feat in zip(predictions, scores, global_features):
        idx = np.where(pred == -1)[0]
        anomalous_windows = [dates[i] for i in idx]
        scores_windows = [score[i] for i in idx]
        for w, s in zip(anomalous_windows, scores_windows):
            tmp_list = output_dict.get(w, [])
            tmp_list.append(f'{feat} : {s}')
            output_dict[w] = tmp_list
    return output_dict