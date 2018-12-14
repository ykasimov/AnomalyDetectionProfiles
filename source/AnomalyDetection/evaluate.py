from features import global_features
from argument_parser import parser_inference
import sys
from utils import get_data, majority_voting
import pickle
import numpy as np
import json


def evaluate(models, scalers, features, verbose=False):
    predictions = []
    for feature_name in global_features:
        X = scalers[feature_name].transform(features[feature_name])
        prediction = models[feature_name]._predict(X)
        if verbose:
            print(f'Feature prediction: {feature_name}')
            print(prediction)
        predictions.append(prediction)
    return predictions


def _load_models(folder):
    models = {}
    for feature_name in global_features:
        path = f'{folder}/{feature_name}_model.pkl'
        with open(path, 'rb') as f:
            models[feature_name] = pickle.load(f)
    return models


def _load_scalers(base_folder):
    folder = base_folder + '/scalers'
    scalers = {}
    for feature_name in global_features:
        path = f'{folder}/{feature_name}_scaler.pkl'
        with open(path, 'rb') as f:
            scalers[feature_name] = pickle.load(f)
    return scalers


def _report(predictions, dates):
    output_dict = {}
    for pred, feat in zip(predictions, global_features):
        idx = np.where(pred == -1)[0]
        anomalous_windows = [dates[i] for i in idx]
        for w in anomalous_windows:
            tmp_list = output_dict.get(w, [])
            tmp_list.append(f'{feat} : -1')
            output_dict[w] = tmp_list
    return output_dict


if __name__ == '__main__':
    # global_features.remove('clientDestinationPortTotalBytesUDPEstablished')
    parameters = parser_inference.parse_args(sys.argv[1:])
    features, dates = get_data(parameters.profiles, feature_names=global_features)
    print(dates)
    models = _load_models(parameters.models)
    scalers = _load_scalers(parameters.models)
    predictions = evaluate(models, scalers, features, parameters.verbose)
    report = _report(predictions, dates)
    with open('report.json', 'w') as fp:
        json.dump(report, fp)
    final_prediction = majority_voting(predictions)
    print(final_prediction)
    anomalies = final_prediction[final_prediction == -1]
    print(len(anomalies) / len(final_prediction))
