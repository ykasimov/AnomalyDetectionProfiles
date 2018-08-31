import numpy as np
from argument_parser import parser_training
import sys
import json
from features import global_features
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, ParameterGrid
from sklearn.svm import OneClassSVM
import pandas as pd


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


def print_evaluation(true_positive,
                     false_positive,
                     true_negative,
                     false_negative,
                     feature_name):
    precision, recall, accuracy = compute_precision_recall_accuracy(true_positive, false_positive, true_negative,
                                                                    false_negative)
    print('===========================================================')
    print(f'Feature name: {feature_name}')
    print(f'tp={true_positive} tn={true_negative} fp={false_positive} fn={false_negative}')
    print(f'False positive rate: {false_positive / (false_positive + true_negative)}')

    print(f'False negative: {1 - false_positive / (false_positive + true_negative)}')
    print('\n')
    print(f'Precision: {precision}')
    print(f'Recall: {recall}')
    print(f'Accuracy: {accuracy}')


def compute_precision_recall_accuracy(true_positive, false_positive, true_negative, false_negative):
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)
    accuracy = (true_positive + true_negative) / (true_positive + true_negative + false_negative + false_positive)
    return precision, recall, accuracy


def get_evaluation_matrix(labels, predicted):
    anomaly_range = (labels == -1)
    benign_range = (labels == 1)
    true_positive = np.sum(predicted[anomaly_range] == labels[anomaly_range])
    false_positive = np.sum(predicted[benign_range] != labels[benign_range])
    true_negative = np.sum(predicted[benign_range] == labels[benign_range])
    false_negative = np.sum(predicted[anomaly_range] != labels[anomaly_range])
    return true_positive, false_positive, true_negative, false_negative


def get_data(file, feature_names):
    with open(file, 'r') as f:
        data = json.load(f)
    ip = list(data.keys())[0]
    profile = data[ip]['time']
    features_per_feature = {feat: [] for feat in feature_names}
    for date, day_profile in profile.items():
        for time_window, histogram in day_profile.items():
            [features_per_feature[feat].append(create_features(histogram[feat])) for feat in feature_names]
    for feat in feature_names:
        features_per_feature[feat] = np.array(features_per_feature[feat])
    return features_per_feature


def _ocvsm_param_search(train_data, validation_data, validation_labels):
    print('Param search')
    parameters = {'gamma': np.logspace(-9, 3, 13), 'nu': np.linspace(0.01, 0.99, 99)}
    experiment_results = pd.DataFrame(columns=['parameters', 'evaluation'] + global_features)
    experiment_results.set_index(['parameters', 'evaluation'], inplace=True)

    for z in ParameterGrid(parameters):
        kernel_string = ', '.join(f'{key} : {val}' for key, val in z.items())
        # print(z)
        for feature_name in global_features:
            svm = OneClassSVM()
            svm.set_params(**z)
            X_train = train_data[feature_name]
            X_val = validation_data[feature_name]
            svm.fit(X_train)
            predicted = svm.predict(X_val)

            true_positive, false_positive, true_negative, false_negative = \
                get_evaluation_matrix(labels=validation_labels, predicted=predicted)

            precision, recall, accuracy = compute_precision_recall_accuracy(true_positive=true_positive,
                                                                            true_negative=true_negative,
                                                                            false_positive=false_positive,
                                                                            false_negative=false_negative)
            experiment_results.loc[(kernel_string, 'tp'), feature_name] = true_positive
            experiment_results.loc[(kernel_string, 'fp'), feature_name] = false_positive
            experiment_results.loc[(kernel_string, 'tn'), feature_name] = true_negative
            experiment_results.loc[(kernel_string, 'fn'), feature_name] = false_negative
            experiment_results.loc[(kernel_string, 'precision'), feature_name] = precision
            experiment_results.loc[(kernel_string, 'recall'), feature_name] = recall
            experiment_results.loc[(kernel_string, 'accuracy'), feature_name] = accuracy
            experiment_results.loc[(kernel_string, ''
                                                   'FPR'), feature_name] = false_positive / (
                    false_positive + true_negative)
            experiment_results.loc[(kernel_string, 'TPR'), feature_name] = true_positive / (
                    true_positive + false_negative)

    return experiment_results


def _select_params_from_results(experiment_results):
    experiment_results = experiment_results.astype(np.float16)
    model_params = {k: {} for k in global_features}
    min_tpr = 0.167  # 0.167*6 = 1.002 it means we will detect an attack during first 30 minutes
    for feature in global_features:
        tmp = experiment_results.unstack(1)[feature]
        tpr_max_val_fpr_less_001 = tmp[tmp['FPR'] < 0.01]['TPR'].max()
        tpr_max_val_fpr_min = tmp[tmp['FPR'] == tmp['FPR'].min()]['TPR'].max()
        # print('=====================\n', feature)
        if tpr_max_val_fpr_min > min_tpr:
            # print(tmp[tmp['FPR'] == tmp['FPR'].min()][['FPR', 'TPR', 'precision', 'recall']])
            params = tmp[tmp['FPR'] == tmp['FPR'].min()]['TPR'].idxmax().split(', ')
        elif tpr_max_val_fpr_less_001 > tpr_max_val_fpr_min:
            # print(tmp[tmp['FPR'] < 0.01][['FPR', 'TPR', 'precision', 'recall']])
            params = tmp[tmp['FPR'] < 0.01]['TPR'].idxmax().split(', ')
        else:
            params = tmp[tmp['FPR'] == tmp['FPR'].min()]['TPR'].idxmax().split(', ')
        for p in params:
            p = p.split(' : ')
            p_name = p[0]
            p_value = float(p[1])
            model_params[feature][p_name] = p_value
    return model_params
    # for feature in global_features:
    #     print(feature, model_params[feature])


def _train_ocsvm(train, params):
    models = {}
    for feature_name in global_features:
        z = params[feature_name]
        svm = OneClassSVM().set_params(**z)
        X_train = train[feature_name]
        svm.fit(X_train)
        models[feature_name] = svm

    return models


def split_train_validation_test(normal_data, malware_data, features):
    X_train = {}
    X_test = {}
    X_val = {}

    for feat in features:
        print('before splitting')
        X_train[feat], X_test[feat], labels_train, labels_test = train_test_split(normal_data[feat],
                                                                                  [1] * normal_data[feat].shape[0],
                                                                                  test_size=0.2,
                                                                                  random_state=42)
        X_train[feat], X_val[feat], labels_train, labels_val = train_test_split(X_train[feat],
                                                                                [1] * X_train[feat].shape[0],
                                                                                test_size=0.25,
                                                                                random_state=42)

        np.random.seed(42)
        idx = np.random.choice(range(0, malware_data[feat].shape[0]), int(malware_data[feat].shape[0] / 2),
                               replace=False)
        validation_anomalies = malware_data[feat][idx, :]
        idx = [x for x in range(malware_data[feat].shape[0]) if x in set(idx)]
        test_anomaly = malware_data[feat][idx, :]

        X_val[feat] = np.append(X_val[feat], validation_anomalies, axis=0)
        X_test[feat] = np.append(X_test[feat], test_anomaly, axis=0)
    train_labels = np.array([1] * X_train[features[0]].shape[0])
    numberof_validation_anomalies = int(malware_data[features[0]].shape[0] / 2)
    val_labels = (np.array([1] * (X_val[features[0]].shape[0] - numberof_validation_anomalies)
                           + [-1] * numberof_validation_anomalies))
    numberof_test_anomalies = malware_data[features[0]].shape[0] - numberof_validation_anomalies
    test_labels = (
        np.array([1] * (X_test[features[0]].shape[0] - numberof_test_anomalies) + [-1] * numberof_test_anomalies))

    return (X_train, train_labels), (X_val, val_labels), (X_test, test_labels)


def test_models(test_data, label_test, models):
    for feature_name in global_features:
        X_test = test_data[feature_name]
        y = label_test[feature_name]
        predictions = models[feature_name].predict(X_test)
        true_positive, false_positive, true_negative, false_negative = \
            get_evaluation_matrix(labels=y, predicted=predictions)
        print(f'{feature_name}: '
              f'FPR={false_positive/(false_positive + true_negative)}'
              f'TPR={true_positive / (true_positive + false_negative)}')


def train(normal_data, malware_data, features, algorithm='OCSVM'):
    train, validation, test = split_train_validation_test(normal_data, malware_data, features)
    X_train = train[0]
    X_val = validation[0]
    X_test = test[0]
    validation_labels = validation[1]
    test_labels = test[1]

    scalers = {feat: StandardScaler(with_std=True, with_mean=True).fit(X_train[feat]) for feat in features}
    for feat in features:
        X_train[feat] = scalers[feat].transform(X_train[feat])
        X_val[feat] = scalers[feat].transform(X_val[feat])
        X_test[feat] = scalers[feat].transform(X_test[feat])
    if algorithm == 'OCSVM':
        # experiment_results = _ocvsm_param_search(X_train, X_val, validation_labels)
        experiment_results = pd.read_pickle('test.pkl')
        params = _select_params_from_results(experiment_results)
        models = _train_ocsvm(X_train, params)
        test_models(X_test, test_labels, models)
        return models
    else:
        raise NotImplementedError('Available algorithms: [OCSVM, LOF]')


if __name__ == '__main__':
    # 1. file with normal
    # 2. file with mix
    import time

    time.sleep(5)
    # print('starting the training')
    parameters = parser_training.parse_args(sys.argv[1:])
    normal_training = get_data(parameters.normal_data, feature_names=global_features)
    print('normal data are prepared')
    malware_data = get_data(parameters.validation_data, feature_names=global_features)
    print('mixed data are prepared')
    models = train(normal_training, malware_data, features=global_features)

    # experiment_results.to_pickle('test.pkl')
    # experiment_results = pd.read_pickle('test.pkl')
    # params = _select_params_from_results(experiment_results)
    print(models)
