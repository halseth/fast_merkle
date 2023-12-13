use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[derive(Clone, Debug)]
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
    fn equal_trees() {
        let size = 67108864;

        let zero_val: Vec<u8> = vec![];
        let mut tree = Tree::new_with_default(size, zero_val.clone()).unwrap();

        let zero_root_str = "1a3cbd2b72d446c559e6bf49e8bccd22546e127baa2d7f559159d851d77482ae";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();
        let root = tree.root();
        assert_eq!(root, zero_root);

        let vals: Vec<(usize, Vec<u8>)> = vec![
            (16128, vec![127, 69, 76, 70]),
            (16129, vec![1, 1, 1]),
            (16132, vec![2, 0, 243, 0]),
            (16133, vec![1]),
            (16134, vec![116, 0, 1]),
            (16135, vec![52]),
            (16136, vec![32, 3]),
            (16138, vec![52, 0, 32]),
            (16139, vec![2, 0, 40]),
            (16140, vec![6, 0, 5]),
            (16141, vec![3, 0, 0, 112]),
            (16142, vec![28, 1]),
            (16145, vec![26]),
            (16147, vec![4]),
            (16148, vec![1]),
            (16149, vec![1]),
            (16151, vec![0, 0, 1]),
            (16152, vec![0, 0, 1]),
            (16153, vec![28, 1]),
            (16154, vec![28, 1]),
            (16155, vec![5]),
            (16156, vec![0, 16]),
            (16157, vec![151, 33]),
            (16158, vec![147, 129, 129, 138, 0]),
            (16159, vec![55, 1, 32]),
            (16160, vec![19, 1, 1, 64]),
            (16161, vec![239, 0, 128, 0]),
            (16162, vec![111, 0, 64, 3]),
            (16163, vec![19, 1, 1, 254, 0]),
            (16164, vec![35, 46, 17]),
            (16165, vec![35, 44, 129, 0]),
            (16166, vec![19, 4, 1, 2]),
            (16167, vec![19, 5, 32]),
            (16168, vec![239, 0, 192, 2]),
            (16169, vec![35, 36, 164, 254, 0]),
            (16170, vec![19, 5]),
            (16171, vec![131, 32, 193, 1]),
            (16172, vec![3, 36, 129, 1]),
            (16173, vec![19, 1, 1, 2]),
            (16174, vec![103, 128, 0]),
            (16175, vec![147, 5, 129, 1]),
            (16176, vec![19, 21, 133, 0]),
            (16177, vec![147, 2]),
            (16178, vec![115]),
            (16179, vec![19, 1, 1, 253, 0]),
            (16180, vec![35, 38, 129, 2]),
            (16181, vec![19, 4, 1, 3]),
            (16182, vec![35, 46, 164, 252, 0]),
            (16183, vec![35, 38, 4, 254, 0]),
            (16184, vec![111, 0, 192, 1]),
            (16185, vec![131, 39, 196, 253, 0]),
            (16186, vec![147, 151, 23]),
            (16187, vec![35, 46, 244, 252, 0]),
            (16188, vec![131, 39, 196, 254, 0]),
            (16189, vec![147, 135, 23]),
            (16190, vec![35, 38, 244, 254, 0]),
            (16191, vec![3, 39, 196, 254, 0]),
            (16192, vec![147, 7, 112]),
            (16193, vec![227, 208, 231, 254, 0]),
            (16194, vec![131, 39, 196, 253, 0]),
            (16195, vec![19, 133, 7]),
            (16196, vec![3, 36, 193, 2]),
            (16197, vec![19, 1, 1, 3]),
            (16198, vec![103, 128, 0]),
            (50331424, vec![116, 0, 1]),
        ];

        for (addr, val) in &vals {
            tree.set_leaf(*addr, (*val).clone().into());
        }

        let new_root = tree.commit();
        let init_exp_root_str = "56ac7fc1a6253af0ed6dc28f2ba3150178aaa9ee783de765c45144e3885732ea";
        let init_exp_root: [u8; 32] = hex::decode(init_exp_root_str).unwrap().try_into().unwrap();

        assert_eq!(new_root, init_exp_root);

        // Alter two of the leaves.
        let set_vals: Vec<(usize, Vec<u8>)> = vec![
            (50331395, vec![0x74, 0x20, 0x01]),
            (50331424, vec![0x78, 0x00, 0x01]),
        ];

        for (addr, val) in &set_vals {
            tree.set_leaf(*addr, (*val).clone().into());
        }

        let new_root = tree.commit();
        let second_exp_root_str =
            "00fea9abf22b0119fbf52222912a2fb0f9879bbb77ec1b571040b35b08b97e3c";
        let second_exp_root: [u8; 32] = hex::decode(second_exp_root_str)
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(new_root, second_exp_root);

        // Build the same tree again, but alter the order of operations.
        let mut second_tree = Tree::new_with_default(size, zero_val.clone()).unwrap();
        for (addr, val) in vals {
            second_tree.set_leaf(addr, val.clone().into());
        }

        let second_root = second_tree.commit();
        assert_eq!(second_root, init_exp_root);

        let second_set_vals: Vec<(usize, Vec<u8>)> = vec![
            (50331424, vec![0x74, 0x00, 0x01]),
            (50331395, vec![0x74, 0x20, 0x01]),
            (50331424, vec![0x78, 0x00, 0x01]),
        ];

        for (addr, val) in second_set_vals {
            second_tree.set_leaf(addr, val.into());
            second_tree.commit();
        }

        let second_altered_root = second_tree.root();
        assert_eq!(second_altered_root, second_exp_root);
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
