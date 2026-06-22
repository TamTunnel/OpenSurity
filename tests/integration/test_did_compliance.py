from opensurity.identity.level2 import Level2Identity

def test_did_compliance(tmp_path):
    l2 = Level2Identity(agent_id="dummy", key_dir=str(tmp_path))
    did, priv_b64 = l2.generate()
    l2.agent_id = did
    
    doc = l2.resolve(did)
    
    assert "@context" in doc
    assert "https://www.w3.org/ns/did/v1" in doc["@context"]
    assert doc["id"] == did
    
    vm = doc["verificationMethod"][0]
    assert vm["type"] == "Ed25519VerificationKey2020"
    assert vm["controller"] == did
    assert vm["publicKeyMultibase"] == did.split(":")[-1]

    assert f"{did}#{vm['publicKeyMultibase']}" in doc["authentication"]
