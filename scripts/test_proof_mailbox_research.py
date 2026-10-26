"""Independent fixed wire vector and unsigned authorization/footprint checks."""
import unittest
from stellar_sdk import StrKey, scval, xdr
from run_proof_mailbox_research import CHUNK, chain, envelope, identifiers


class ProofMailboxWireTests(unittest.TestCase):
    def setUp(self):
        self.config = {"network_id_hex": (bytes([11])*32).hex(),
            "parent":StrKey.encode_contract(bytes([85])*32),
            "uploader":StrKey.encode_ed25519_public_key(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")),
            "nonce_hex":(bytes([1])*32).hex(),"statement_hex":(bytes([2])*64).hex(),
            "verifier_hex":(bytes([3])*32).hex(),"parameters_hex":(bytes([4])*32).hex(),"length":3,"expires":1900}
        self.config["session_id_hex"]=identifiers(self.config).hex()

    def test_golden_wire_vector_shared_with_actual_rust_contract(self):
        identifier,root=chain(self.config,b"abc")
        self.assertEqual(identifier.hex(),"a590ddb4f40041806723a7812b49ed2db6579e10b34b75cf83e2b064fb97e8f0")
        self.assertEqual(root.hex(),"ea722d8105e36658bed92c358268470d9ab4b4055b0d0e076331f74b6490fab2")

    def test_all_immutable_header_inputs_change_session_identity(self):
        changes={"network_id_hex":(bytes([12])*32).hex(),"parent":StrKey.encode_contract(bytes([86])*32),
                 "uploader":StrKey.encode_ed25519_public_key(bytes([7])*32),"nonce_hex":(bytes([9])*32).hex(),
                 "statement_hex":(bytes([9])*64).hex(),"verifier_hex":(bytes([9])*32).hex(),
                 "parameters_hex":(bytes([9])*32).hex(),"length":4,"expires":1901}
        for field,value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(identifiers(self.config),identifiers(dict(self.config,**{field:value})))

    def test_source_account_authorization_matches_exact_invocation(self):
        args=[scval.to_bytes(bytes.fromhex(self.config["session_id_hex"])),scval.to_uint32(0),scval.to_bytes(bytes(CHUNK))]
        raw=envelope(self.config,"append",args,"aa"*32,chunk_index=0,authorize=True)
        decoded=xdr.TransactionEnvelope.from_xdr_bytes(raw)
        operation=decoded.v1.tx.operations[0].body.invoke_host_function_op
        self.assertEqual(len(operation.auth),1)
        self.assertEqual(operation.auth[0].credentials.type,xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT)
        self.assertEqual(operation.auth[0].root_invocation.function.contract_fn.to_xdr_bytes(),operation.host_function.invoke_contract.to_xdr_bytes())
        self.assertLessEqual(len(raw),132096)
        self.assertEqual(len(decoded.v1.tx.ext.soroban_data.resources.footprint.read_write),2)

    def test_moving_or_replacing_chunks_changes_commitment(self):
        first=dict(self.config,length=CHUNK+1)
        data=bytes([1])*CHUNK+b"b"
        self.assertNotEqual(chain(first,data)[1],chain(first,data[1:]+data[:1])[1])
        self.assertNotEqual(chain(first,data)[1],chain(first,data[:-1]+b"c")[1])


if __name__=="__main__":
    unittest.main()
