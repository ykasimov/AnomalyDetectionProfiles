from features import global_features
from argument_parser import parser_inference
import sys
from utils import get_data, majority_voting
import pickle


def evaluate(models, features):
    predictions = []
    for feature_name in global_features:
        prediction = models[feature_name].predict(features[feature_name])
        predictions.append(prediction)
    return predictions


def _load_models(folder):
    models = {}
    for feature_name in global_features:
        path = f'{folder}/{feature_name}_model.pkl'
        with open(path, 'rb') as f:
            models[feature_name] = pickle.load(f)
    return models


if __name__ == '__main__':

    global_features.remove('clientDestinationPortTotalBytesUDPEstablished')
    parameters = parser_inference.parse_args(sys.argv[1:])
    features = get_data(parameters.profiles, feature_names=global_features)
    models = _load_models(parameters.models)
    predictions = evaluate(models, features)
    final_prediction = majority_voting(predictions)
    print(final_prediction)
