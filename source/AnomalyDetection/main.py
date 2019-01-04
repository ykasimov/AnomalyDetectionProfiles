import profiles
from argument_parser import parser
import sys
import train
import evaluate
import utils
from features import global_features
import json

if __name__ == '__main__':
    parameters = parser.parse_args(sys.argv[1:])

    if not parameters.models:
        profiles_train = profiles.create_profiles(parameters.ip, parameters.train_file,
                                                  parameters.file_to_save + '_train')
        profiles_validation = profiles.create_profiles(parameters.ip,
                                                       parameters.validation_file,
                                                       parameters.file_to_save + '_validation')

        models, scalers = train.train(parameters, profiles_train, profiles_validation)
    else:
        models = utils.load_models(parameters.models)
        scalers = utils.load_scalers(parameters.models)

    profiles_test = profiles.create_profiles(parameters.ip, parameters.validation_file,
                                             parameters.file_to_save + '_test')
    features, dates = utils.get_data(parameters.profiles, feature_names=global_features, data=profiles_test)
    predictions, scores = evaluate.evaluate(models, scalers, features, parameters.verbose)
    report = utils.report(predictions, scores, dates)
    with open('report.json', 'w') as fp:
        json.dump(report, fp)
    final_prediction = utils.majority_voting(predictions)
    print(final_prediction)
    anomalies = final_prediction[final_prediction == -1]
    print(len(anomalies) / len(final_prediction))
