from features import global_features
from argument_parser import parser_inference
import sys
from utils import get_data, majority_voting, load_models, load_scalers, report
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


if __name__ == '__main__':
    # global_features.remove('clientDestinationPortTotalBytesUDPEstablished')
    parameters = parser_inference.parse_args(sys.argv[1:])
    features, dates = get_data(parameters.profiles, feature_names=global_features)
    models = load_models(parameters.models)
    scalers = load_scalers(parameters.models)
    predictions, scores = evaluate(models, scalers, features, parameters.verbose)
    report = report(predictions, scores, dates)
    with open('report.json', 'w') as fp:
        json.dump(report, fp)
    final_prediction = majority_voting(predictions)
    print(final_prediction)
    anomalies = final_prediction[final_prediction == -1]
    print(len(anomalies) / len(final_prediction))
