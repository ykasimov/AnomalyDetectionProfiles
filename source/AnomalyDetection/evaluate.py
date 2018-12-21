from features import global_features
from argument_parser import parser_inference
import sys
from utils import get_data, majority_voting
import pickle
import numpy as np
import json


def evaluate(models, scalers, features, verbose=False):
    predictions = []
    scores = []
    for feature_name in global_features:
        X = scalers[feature_name].transform(features[feature_name])
        prediction = models[feature_name].predict(X)
        score = models[feature_name].score_samples(X)
        if verbose:
            print(f'Feature prediction: {feature_name}')
            print(prediction)
        predictions.append(prediction)
        scores.append(score)
    return predictions, scores


def _load_models(folder):
    models = {}
    for feature_name in global_features:
        path = f'{folder}/{feature_name}_model.pkl'
        with open(path, 'rb') as f:
            models[feature_name] = pickle.load(f).set_params(novelty=True)

    return models


def _load_scalers(base_folder):
    folder = base_folder + '/scalers'
    scalers = {}
    for feature_name in global_features:
        path = f'{folder}/{feature_name}_scaler.pkl'
        with open(path, 'rb') as f:
            scalers[feature_name] = pickle.load(f)
    return scalers


def _report(predictions, scores, dates):
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


if __name__ == '__main__':
    # global_features.remove('clientDestinationPortTotalBytesUDPEstablished')
    parameters = parser_inference.parse_args(sys.argv[1:])
    features, dates = get_data(parameters.profiles, feature_names=global_features)
    models = _load_models(parameters.models)
    scalers = _load_scalers(parameters.models)
    predictions, scores = evaluate(models, scalers, features, parameters.verbose)
    report = _report(predictions, scores, dates)
    with open('report.json', 'w') as fp:
        json.dump(report, fp)
    final_prediction = majority_voting(predictions)
    print(final_prediction)
    anomalies = final_prediction[final_prediction == -1]
    print(len(anomalies) / len(final_prediction))
