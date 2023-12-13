use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub struct Tree {
    size: usize,
    dirty: bool,
    leaves: Vec<Vec<u8>>,
    updates: VecDeque<usize>,
    zero_hashes: Vec<[u8; 32]>,
    node_map: HashMap<usize, [u8; 32]>,
}

#[derive(Debug)]
pub struct SizeError {
    message: String,
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for SizeError {}

#[derive(Debug)]
pub struct InvalidValueError {
    message: String,
}

impl fmt::Display for InvalidValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl Error for InvalidValueError {}

impl Tree {
    pub fn new(size: usize) -> Result<Self, SizeError> {
        Self::new_with_default(size, vec![])
    }

    pub fn new_with_default(size: usize, zero_val: Vec<u8>) -> Result<Self, SizeError> {
        if !usize::is_power_of_two(size) {
            return Err(SizeError {
                message: "not power of two".to_string(),
            });
        }

        // all leaves start out empty.
        let leaves = vec![zero_val.clone(); size];
        let updates = VecDeque::new();
        let zero_hashes = Self::zero_hashes(size, zero_val);
        let node_map = HashMap::new();

        let s = Self {
            size,
            dirty: true,
            leaves,
            updates,
            zero_hashes,
            node_map,
        };

        Ok(s)
    }

    fn zero_hashes(size: usize, zero_val: Vec<u8>) -> Vec<[u8; 32]> {
        // Size is a power of two.
        let num_levels = (size.ilog2() + 1) as usize;
        let mut zeros = vec![[0u8; 32]; num_levels];

        for lev in (0..num_levels).rev() {
            let data: Vec<u8> = {
                // Leaf node.
                if lev == num_levels - 1 {
                    zero_val.clone()
                } else {
                    let mut child = zeros[lev + 1].to_vec();
                    child.append(&mut child.clone());
                    child
                }
            };

            let mut hasher = Sha256::new();
            hasher.update(data.as_slice());
            let hash = hasher.finalize();
            let hash_array: [u8; 32] = hash.into();

            zeros[lev] = hash_array;
        }

        zeros
    }

    pub fn get_leaf(&mut self, i: usize) -> Vec<u8> {
        self.leaves[i].clone()
    }

    pub fn set_leaf(&mut self, i: usize, val: Vec<u8>) {
        // First check if changes at all. This avoids an expensive hashing.
        let pre = self.leaves[i].clone();
        if pre == val {
            return;
        }

        self.leaves[i] = val.clone();
        let node = self.size - 1 + i;
        self.updates.push_back(node);
        self.dirty = true;
    }

    fn get_node(&self, index: usize) -> [u8; 32] {
        match self.node_map.get(&index) {
            Some(v) => v.clone(),
            None => {
                let level = (index + 1).ilog2() as usize;
                self.zero_hashes[level]
            }
        }
    }

    pub fn commit(&mut self) -> [u8; 32] {
        // Iterate updates.
        let mut last_update: usize = 0;
        while !self.updates.is_empty() {
            let node = self.updates.pop_front().unwrap();

            // Skip double updates in case both children were updated.
            if node == last_update {
                continue;
            }

            let mut data: Vec<u8> = vec![];
            let mut hasher = Sha256::new();

            // Leaves start at index size-1;
            if node < self.size - 1 {
                let c0 = 2 * node + 1;
                let c1 = 2 * node + 2;

                let child0 = self.get_node(c0);
                let child1 = self.get_node(c1);

                data.extend_from_slice(&child0);
                data.extend_from_slice(&child1);
            } else {
                let leaf = &self.leaves[node + 1 - self.size];
                data.extend_from_slice(&leaf);
            }

            hasher.update(data.as_slice());
            let hash = hasher.finalize();
            let hash_array: [u8; 32] = hash.into();

            self.node_map.insert(node, hash_array);
            last_update = node;

            // Push parent node to updates.
            if node != 0 {
                self.updates.push_back((node - 1) / 2);
            }
        }

        self.dirty = false;

        // Return new root.
        self.get_node(0)
    }

    pub fn root(&self) -> [u8; 32] {
        self.get_node(0)
    }

    pub fn proof(&self, i: usize, val: Vec<u8>) -> Result<Vec<[u8; 32]>, InvalidValueError> {
        let pre = self.leaves[i].clone();
        if val != pre {
            return Err(InvalidValueError {
                message: "leaf value mismatch".to_string(),
            });
        }

        if self.dirty {
            return Err(InvalidValueError {
                message: "tree dirty, need commit".to_string(),
            });
        }

        let mut proof: Vec<[u8; 32]> = vec![];

        let mut node = self.size - 1 + i;
        while node > 0 {
            let sibling_index = match node % 2 {
                0 => node - 1,
                _ => node + 1,
            };

            let sibling = self.get_node(sibling_index);
            proof.push(sibling);

            node = (node - 1) / 2;
        }

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn invalid_size() {
        let tree = Tree::new(5);
        match tree {
            Err(_) => {}
            _ => panic!("expected size error"),
        }
    }

    #[test]
    fn new() {
        let size = 4;
        let tree = Tree::new(size).unwrap();
        assert_eq!(tree.leaves.len(), size);

        let zero_root_str = "5310a330e8f970388503c73349d80b45cd764db615f1bced2801dcd4524a2ff4";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();

        let root = tree.root();
        assert_eq!(root, zero_root);
        assert_eq!(root, tree.zero_hashes[0]);
    }

    #[test]
    fn new_with_default() {
        let size = 4;
        let mut tree = Tree::new_with_default(size, vec![0]).unwrap();
        assert_eq!(tree.leaves.len(), size);

        let zero_root_str = "f8d3ccccb4c4e6d5e2fefbff8c68aaf58d56528e3b6d8ebf07b4210cefe6a1f1";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();

        let root = tree.root();
        assert_eq!(root, zero_root);
        assert_eq!(root, tree.zero_hashes[0]);

        // Set empty value.
        let new_leaf: Vec<u8> = vec![];
        tree.set_leaf(0, new_leaf);
        let new_root = tree.commit();

        let new_exp_root_str = "64fe74bdcb7067d34f436ad40d8fe7918d20f4d46cb62e66e15b8b499bcf72a1";
        let new_exp_root: [u8; 32] = hex::decode(new_exp_root_str).unwrap().try_into().unwrap();

        assert_eq!(new_root, new_exp_root);
    }
    #[test]
    fn large_new() {
        let size = 1 << 24;
        let tree = Tree::new(size).unwrap();
        assert_eq!(tree.leaves.len(), size);
    }

    #[test]
    fn alter() {
        let size = 4;
        let mut tree = Tree::new(size).unwrap();
        let zero_root_str = "5310a330e8f970388503c73349d80b45cd764db615f1bced2801dcd4524a2ff4";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();
        let root = tree.root();
        assert_eq!(root, zero_root);

        let new_leaf: Vec<u8> = vec![1, 1, 1];

        tree.set_leaf(0, new_leaf);
        let new_root = tree.commit();

        let exp_root_str = "05c04dbe678c7af523966fab4b8b97f7fc61a431325cb08e232a5f0f448bc9e1";
        let exp_root: [u8; 32] = hex::decode(exp_root_str).unwrap().try_into().unwrap();

        assert_eq!(new_root, exp_root);
    }

    #[test]
    fn double_alter() {
        let size = 4;
        let mut tree = Tree::new(size).unwrap();
        let zero_root_str = "5310a330e8f970388503c73349d80b45cd764db615f1bced2801dcd4524a2ff4";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();
        let root = tree.root();
        assert_eq!(root, zero_root);

        let new_leaf: Vec<u8> = vec![1, 1, 1];
        let new_leaf2: Vec<u8> = vec![2, 2, 2];

        tree.set_leaf(0, new_leaf);
        tree.set_leaf(3, new_leaf2);
        let new_root = tree.commit();

        let exp_root_str = "afafdad52f016467f2e29867d3adde09133708ba0b4dab04a8cd538b78cc487d";
        let exp_root: [u8; 32] = hex::decode(exp_root_str).unwrap().try_into().unwrap();

        assert_eq!(new_root, exp_root);
    }
    #[test]
    fn proof() {
        let size = 4;
        let mut tree = Tree::new(size).unwrap();

        let new_leaf: Vec<u8> = vec![1];
        let new_leaf2: Vec<u8> = vec![2];

        tree.set_leaf(0, new_leaf.clone());
        tree.set_leaf(3, new_leaf2.clone());
        let new_root = tree.commit();

        let exp_root_str = "8a541763389ec48a3243be754f488605d58302f7c7a5a8062cd06cc1eb22c02c";
        let exp_root: [u8; 32] = hex::decode(exp_root_str).unwrap().try_into().unwrap();
        assert_eq!(new_root, exp_root);

        let exp_proof_str = vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "00b1f83e1e9716fc95bb15a9ce5307ec679af9c45d9e29c8e1a2de42993a7a16",
        ];

        let mut exp_proof: Vec<[u8; 32]> = vec![];
        for x in exp_proof_str {
            let h = hex::decode(x).unwrap();
            exp_proof.push(h.try_into().unwrap());
        }

        let proof = tree.proof(0, new_leaf).unwrap();
        assert_eq!(exp_proof, proof);

        let exp_proof2_str = vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "0cb82415a7954f417a53ff5728d138e2139ab4ecfd5c824cb3ce378875324dd2",
        ];

        let mut exp_proof2: Vec<[u8; 32]> = vec![];
        for x in exp_proof2_str {
            let h = hex::decode(x).unwrap();
            exp_proof2.push(h.try_into().unwrap());
        }

        let proof2 = tree.proof(3, new_leaf2).unwrap();
        assert_eq!(exp_proof2, proof2);
    }
}
