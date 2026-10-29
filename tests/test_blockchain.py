from cyber_resilient_cloud.blockchain.chain import append_block, create_chain, validate_chain


def test_append_and_validate_chain():
    chain = create_chain()
    append_block(chain, "alert", {"source": "shield"})
    append_block(chain, "vault", {"source": "vault"})

    assert len(chain["blocks"]) == 3
    assert validate_chain(chain) is True


def test_validate_chain_detects_tampering():
    chain = create_chain()
    append_block(chain, "alert", {"source": "shield"})
    chain["blocks"][1]["payload"]["source"] = "tampered"

    assert validate_chain(chain) is False
