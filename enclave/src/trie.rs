use rlp::Rlp;

use crate::{
    error::{ProofVerificationError, ProofVerificationResult},
    eth::{aliases::B256, proof::ProofResponse},
    timing::{Lap, Timings},
    utils::keccak256,
};

pub fn verify_proof(
    resp: ProofResponse,
    state_root: &[u8],
    timings: &mut Timings,
) -> ProofVerificationResult<Vec<(B256, Option<Vec<u8>>)>> {
    // 1. Verify the account proof
    let lap_account = Lap::new("verify_mpt_proof::account");
    let address = resp.address.0.as_slice();
    let storage_root = verify_account_proof(&resp, state_root, address)?;
    lap_account.stop(timings);

    assert_eq!(
        resp.storage_hash.0.as_slice(),
        storage_root,
        "Account storage root does not match"
    );

    // 2. Verify the storage proof
    let lap_storage = Lap::new("verify_mpt_proof::storage");
    let values = verify_storage_proof(&resp, &storage_root)?;
    lap_storage.stop(timings);

    Ok(values)
}

fn verify_account_proof(
    proof: &ProofResponse,
    state_root: &[u8],
    address: &[u8],
) -> ProofVerificationResult<Vec<u8>> {
    let mut current_hash = state_root.to_vec();
    let depth_ap = proof.account_proof.len();
    let account_path_as_str = proof.account_proof.clone();

    let address_hash = hex::encode(keccak256(address));
    let account_key_nibbles = address_hash
        .chars()
        .map(|x| x.to_digit(16).unwrap() as usize)
        .collect::<Vec<_>>();
    let account_key_ptrs = get_key_ptrs(account_path_as_str);

    for (i, p) in proof.account_proof.iter().enumerate() {
        let proof_bytes = hex::decode(p.strip_prefix("0x").unwrap())?;
        let node_bytes = proof_bytes.as_ref();
        let node_hash = keccak256(node_bytes);

        if i == 0 {
            tracing::debug!("Computed hash: {}", hex::encode(node_hash));
            tracing::debug!("Expected state_root: {}", hex::encode(state_root));
            if node_bytes.len() < 32 {
                // TODO: is it irrelevant?
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
    Err(ProofVerificationError::AccountProofFailed)
}

fn verify_storage_proof(
    proof: &ProofResponse,
    storage_root: &[u8],
) -> ProofVerificationResult<Vec<(B256, Option<Vec<u8>>)>> {
    let mut values = Vec::new();

    for proof in proof.storage_proof.iter() {
        let mut current_hash = storage_root.to_vec();
        let storage_key_bytes = proof.key.0.as_slice();
        let key_hash_bytes = keccak256(storage_key_bytes);
        let storage_key_hash = hex::encode(key_hash_bytes);
        let key_nibbles = storage_key_hash
            .chars()
            .map(|x| x.to_digit(16).unwrap() as usize)
            .collect::<Vec<_>>();

        let storage_proof_str = proof.proof.clone();

        let key_ptrs = get_key_ptrs(storage_proof_str);

        for (i, p) in proof.proof.iter().enumerate() {
            let proof_bytes = hex::decode(p.strip_prefix("0x").unwrap())?;
            let node_bytes = proof_bytes.as_ref();
            let node_hash = keccak256(node_bytes);

            if node_bytes.len() < 32 {
                assert_eq!(node_bytes, current_hash.as_slice());
            } else {
                assert_eq!(node_hash, current_hash.as_slice());
            }

            let decoded = Rlp::new(node_bytes);

            if i < proof.proof.len() - 1 {
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
                            return Err(ProofVerificationError::StorageProofInvalidNode(i));
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
                // Handle the last node in the proof
                let item_count = decoded.item_count()?;
                match item_count {
                    2 => {
                        let value_decoded = decoded.at(1)?;
                        if value_decoded.is_data() {
                            let raw = value_decoded.as_raw();
                            let value: Vec<u8> = rlp::decode(raw)?;
                            values.push((proof.key, Some(value)));
                        } else {
                            // empty value case
                            values.push((proof.key, None));
                        }
                    }
                    17 => {
                        // branch node => key doesn't exist
                        tracing::debug!(
                            "Storage slot {:?} does not exist (proof ends at branch node)",
                            proof.key
                        );
                        values.push((proof.key, None));
                    }
                    _ => {
                        tracing::warn!(
                            "Unexpected node type in storage proof: {} items",
                            item_count
                        );
                        values.push((proof.key, None));
                    }
                }
            }
        }
        if !values.iter().any(|(k, _)| *k == proof.key) {
            values.push((proof.key, None));
        }
    }

    Ok(values)
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
