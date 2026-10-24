import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sn.scheme import DomainParams, gen_rcv, gen_sd, setup  # noqa: E402

SUITES = ["classical", "pq"]


@pytest.fixture(params=SUITES)
def suite(request):
    return request.param


@pytest.fixture
def party(suite):
    """A domain parameter set plus one sender and one receiver."""
    dp = setup(suite)
    sk_sd, pk_sd = gen_sd(dp)
    sk_rcv, pk_rcv = gen_rcv(dp)
    return dp, sk_sd, pk_sd, sk_rcv, pk_rcv
