use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use anyhow::{anyhow, Result};
use rlp::Rlp;

use crate::utils::keccak256;

pub fn verify_proof(
    resp: EIP1186AccountProofResponse,
    enc_block_header: Vec<u8>,
) -> Result<String> {
    let rlp_enc_block_header = Rlp::new(&enc_block_header);
    let state_root = rlp_enc_block_header.at(3)?.data()?;

    tracing::info!("Extracted state_root: {}", hex::encode(state_root));

    // 1. Verify the account proof
    let address = resp.address.0.as_slice();
    let storage_root = verify_account_proof(&resp, state_root, address)?;

    // 2. Verify the storage proof
    let value = verify_storage_proof(&resp, &storage_root)?;

    // 3. Verify the block header
    verify_block_header(state_root, &enc_block_header)?;

    // 4. Decode the value
    let bytes = hex::decode(value).expect("Invalid hex in RLP encoded string");
    let rlp = Rlp::new(&bytes);
    // TODO: u64 is not the correct type for the value
    let decoded: u64 = rlp.as_val().expect("Failed to decode RLP");

    Ok(decoded.to_string())
}

fn verify_account_proof(
    proof: &EIP1186AccountProofResponse,
    state_root: &[u8],
    address: &[u8],
) -> Result<Vec<u8>> {
    let mut current_hash = state_root.to_vec();
    let depth_ap = proof.account_proof.len();
    let account_path_as_str = proof
        .account_proof
        .iter()
        .map(|element| format!("0x{}", hex::encode(element.as_ref())))
        .collect::<Vec<String>>();

    let address_hash = hex::encode(keccak256(address));
    let account_key_nibbles = address_hash
        .chars()
        .map(|x| x.to_digit(16).unwrap() as usize)
        .collect::<Vec<_>>();
    let account_key_ptrs = get_key_ptrs(account_path_as_str);

    for (i, p) in proof.account_proof.iter().enumerate() {
        let node_bytes = p.as_ref();
        let node_hash = keccak256(node_bytes);

        if i == 0 {
            tracing::info!("Computed hash: {}", hex::encode(node_hash));
            tracing::info!("Expected state_root: {}", hex::encode(state_root));
            if node_bytes.len() < 32 {
                assert_eq!(
                    node_bytes, state_root,
                    "Inlined first node does not match state_root"
                );
            } else {
                assert_eq!(
                    node_hash, state_root,
                    "Hashed first node does not match state_root"
                );
            }
        }

        assert_eq!(node_hash.as_slice(), current_hash.as_slice());

        let decoded_list = Rlp::new(node_bytes);
        assert!(decoded_list.is_list());

        if i < depth_ap - 1 {
            let nibble = account_key_nibbles[account_key_ptrs[i]];
            current_hash = decoded_list.iter().collect::<Vec<_>>()[nibble]
                .data()?
                .to_vec();
        } else {
            let leaf_node = decoded_list.iter().collect::<Vec<_>>();
            assert_eq!(leaf_node.len(), 2);
            let value_decoded = Rlp::new(leaf_node[1].data().unwrap());
            assert!(value_decoded.is_list());

            let storage_root = value_decoded.iter().collect::<Vec<_>>()[2].data()?;
            assert_eq!(
                proof.storage_hash.0.as_slice(),
                storage_root,
                "Account storage root does not match"
            );
            return Ok(storage_root.to_vec());
        }
    }
    Err(anyhow!("Failed to verify account proof"))
}

fn verify_storage_proof(
    proof: &EIP1186AccountProofResponse,
    storage_root: &[u8],
) -> Result<String> {
    let mut current_hash = storage_root.to_vec();

    let storage_key_bytes = proof.storage_proof[0].key.0.as_slice();
    let key_hash_bytes = keccak256(storage_key_bytes);
    let storage_key_hash = hex::encode(key_hash_bytes);
    let key_nibbles = storage_key_hash
        .chars()
        .map(|x| x.to_digit(16).unwrap() as usize)
        .collect::<Vec<_>>();

    let storage_proof_str = proof.storage_proof[0]
        .proof
        .iter()
        .map(|element| element.to_string())
        .collect::<Vec<String>>();
    let key_ptrs = get_key_ptrs(storage_proof_str);

    for (i, p) in proof.storage_proof[0].proof.iter().enumerate() {
        let node_bytes = p.as_ref();
        let node_hash = keccak256(node_bytes);

        if node_bytes.len() < 32 {
            assert_eq!(node_bytes, current_hash.as_slice());
        } else {
            assert_eq!(node_hash, current_hash.as_slice());
        }

        let decoded = Rlp::new(node_bytes);

        if i < proof.storage_proof[0].proof.len() - 1 {
            match decoded.item_count()? {
                2 => {
                    let next_node = decoded.at(1)?;

                    if next_node.is_data() && next_node.data()?.len() >= 32 {
                        current_hash = next_node.data()?.to_vec();
                    } else {
                        current_hash = next_node.as_raw().to_vec();
                    }
                }
                x => {
                    if x <= 2 {
                        return Err(anyhow!("Invalid node count"));
                    }
                    let nibble = key_nibbles[key_ptrs[i]];
                    let next_node = decoded.at(nibble)?;

                    if next_node.is_data() && next_node.data()?.len() >= 32 {
                        current_hash = next_node.data()?.to_vec();
                    } else {
                        current_hash = next_node.as_raw().to_vec();
                    }
                }
            };
        } else {
            assert_eq!(decoded.item_count()?, 2);
            let value_decoded = decoded.at(1)?;
            assert!(value_decoded.is_data());
            let raw = value_decoded.as_raw();
            let inner: Vec<u8> =
                rlp::decode(raw).map_err(|e| anyhow!("Failed to decode inner value: {:?}", e))?;
            let value = hex::encode(inner);
            return Ok(value);
        }
    }

    Err(anyhow!("Failed to verify storage proof"))
}

fn verify_block_header(storage_root: &[u8], enc_block_header: &[u8]) -> Result<()> {
    let rlp_enc_block_header = Rlp::new(enc_block_header);
    let rlp_state_root = rlp_enc_block_header.at(3)?.data()?;
    assert_eq!(rlp_state_root, storage_root);
    Ok(())
}

fn get_key_ptrs(proof: Vec<String>) -> Vec<usize> {
    let mut result = Vec::<usize>::new();
    let mut key_index = 0;

    for (i, p) in proof.iter().enumerate() {
        let bytes = hex::decode(&p[2..]).expect("Decoding failed");
        let mut in_res: Vec<String> = Vec::new();
        let decoded_list = Rlp::new(&bytes);
        for value in decoded_list.iter() {
            let hex_representation = format!("0x{}", hex::encode(value.data().unwrap()));
            in_res.push(hex_representation);
        }

        if in_res.len() > 2 {
            //branch node
            result.push(key_index);
            key_index += 1;
        } else if i != proof.len() - 1 && in_res.len() == 2 {
            //extension node
            let extension = &in_res[0][2..];
            let bytes = hex::decode(extension).expect("Decoding failed");
            let decoded: String = rlp::decode(&bytes).expect("Decoding failed");
            result.push(key_index);
            key_index += decoded.len();
        } else if i == proof.len() - 1 && in_res.len() == 2 {
            //leaf node
            result.push(key_index);
        }
    }
    result
}
