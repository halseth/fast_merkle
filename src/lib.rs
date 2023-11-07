use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub struct Tree {
    size: usize,
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

impl Tree {
    pub fn new(size: usize) -> Result<Self, SizeError> {
        if !usize::is_power_of_two(size) {
            return Err(SizeError {
                message: "not power of two".to_string(),
            });
        }

        // all leaves start out empty.
        let leaves = vec![vec![]; size];
        let updates: VecDeque<usize> = VecDeque::new();
        let zero_hashes = Self::zero_hashes(size);
        let node_map = HashMap::new();

        let s = Self {
            size,
            leaves,
            updates,
            zero_hashes,
            node_map,
        };

        Ok(s)
    }

    fn zero_hashes(size: usize) -> Vec<[u8; 32]> {
        // Size is a power of two.
        let num_levels = (size.ilog2() + 1) as usize;
        let mut zeros = vec![[0u8; 32]; num_levels];

        for lev in (0..num_levels).rev() {
            let data: Vec<u8> = {
                // Leaf node.
                if lev == num_levels - 1 {
                    vec![]
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

    pub fn set_leaf(&mut self, i: usize, val: Vec<u8>) {
        // First check if changes at all. This avoids an expensive hashing.
        let pre = self.leaves[i].clone();
        if pre == val {
            return;
        }

        self.leaves[i] = val;
        let node = self.size - 1 + i;
        self.updates.push_back(node);
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

        // Return new root.
        self.get_node(0)
    }

    pub fn root(&self) -> [u8; 32] {
        self.get_node(0)
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
}
