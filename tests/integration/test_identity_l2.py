from opensurity.identity.level2 import Level2Identity

def test_l2_generate_and_sign(tmp_path):
    l2 = Level2Identity(agent_id="dummy", key_dir=str(tmp_path))
    did, priv_b64 = l2.generate()
    l2.agent_id = did
    l2.save(priv_b64)

    assert did.startswith("did:key:z")

    msg = b"hello world"
    sig = l2.sign(msg)
    
    assert l2.verify(msg, sig, did)
    assert not l2.verify(b"bad world", sig, did)

def test_l2_load(tmp_path):
    l2 = Level2Identity(agent_id="dummy", key_dir=str(tmp_path))
    did, priv_b64 = l2.generate()
    l2.agent_id = did
    l2.save(priv_b64)
    
    l2_new = Level2Identity(agent_id=did, key_dir=str(tmp_path))
    l2_new.load()
    
    msg = b"hello"
    sig = l2.sign(msg)
    assert l2_new.verify(msg, sig, did)
