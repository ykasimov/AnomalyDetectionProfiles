import pytest
import utils
import numpy as np


@pytest.mark.parametrize("labels, prediction", [(np.array([-1, -1, 1, 1]), np.array([1, -1, -1, 1]))])
def test_true_positive(labels, prediction):
    true_positive, false_positive, true_negative, false_negative = utils.get_evaluation_matrix(labels, prediction)
    assert true_positive == 1


@pytest.mark.parametrize("labels, prediction",
                         [(np.array([-1, -1, 1, 1]), np.array([1, -1, -1, 1]))])
def test_false_positive(labels, prediction):
    true_positive, false_positive, true_negative, false_negative = utils.get_evaluation_matrix(labels, prediction)
    assert false_positive == 1


@pytest.mark.parametrize("labels, prediction",
                         [(np.array([1, 1, 1, -1]), np.array([-1, -1, -1, 1]))])
def test_false_positive_1(labels, prediction):
    true_positive, false_positive, true_negative, false_negative = utils.get_evaluation_matrix(labels, prediction)
    assert false_positive == 3


@pytest.mark.parametrize("labels, prediction",
                         [(np.array([1, 1, 1, -1]), np.array([1, 1, -1, 1]))])
def test_true_negative(labels, prediction):
    true_positive, false_positive, true_negative, false_negative = utils.get_evaluation_matrix(labels, prediction)
    assert true_negative == 2


@pytest.mark.parametrize("labels, prediction",
                         [(np.array([-1, -1, 1, -1]), np.array([1, 1, -1, 1]))])
def test_false_negative(labels, prediction):
    true_positive, false_positive, true_negative, false_negative = utils.get_evaluation_matrix(labels, prediction)
    assert false_negative == 3


@pytest.mark.parametrize("predictions",
                         [(np.array([-1, -1, 1, -1]), np.array([1, 1, -1, 1]), np.array([-1, -1, 1, -1]))])
def test_majority_voting(predictions):
    majority_voting = utils.majority_voting(predictions)
    np.testing.assert_array_equal([-1, -1, 1, -1], majority_voting)


@pytest.mark.parametrize("predictions",
                         [(np.array([-1, -1, 1, -1]),
                           np.array([1, 1, -1, 1]),
                           np.array([-1, -1, 1, -1]),
                           np.array([1, 1, 1, 1]))])
def test_majority_voting_equal_votes(predictions):
    majority_voting = utils.majority_voting(predictions)
    np.testing.assert_array_equal([-1, -1, 1, -1], majority_voting)
