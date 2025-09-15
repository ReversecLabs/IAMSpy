import pytest

from iamspy import Model


@pytest.fixture
def model() -> Model:
    return Model()


@pytest.fixture
def req():
    return {
        "source": "",
        "action": "",
        "resource": "",
    }
