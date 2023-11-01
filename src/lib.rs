use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use sha2::{Sha256, Digest};

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub struct Tree {
    size: usize,
    leaves: Vec<Vec<u8>>,
    tree: Vec<[u8; 32]>,
    updates: VecDeque<usize>,
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
        let tree: Vec<[u8; 32]> = vec![[0; 32]; 2*size-1];
        let leaves = vec![vec![]; size];
        let updates: VecDeque<usize> = VecDeque::new();
        let mut s = Self {
            size,
            leaves,
            tree,
            updates,
        };

        // update all leaves.
        for i in 0..size {
            s.set_leaf(i, vec![]);
        }

        s.commit();
        Ok(s)
    }

    pub fn set_leaf(&mut self, i: usize, val: Vec<u8>) {
        self.leaves[i] = val;
        let node= self.size-1+i;
        self.updates.push_back(node);
        println!("pushing back leaf={} node={}", i, node);
    }

    pub fn commit(&mut self) -> [u8; 32]{

        // Iterate updates.
        let mut last_update: usize = 0;
        while !self.updates.is_empty() {
            let node = self.updates.pop_front().unwrap();

            println!("node to update={}", node);

            // Skip double updates in case both children were updated.
            if node == last_update {
                println!("skippint double node update={}", node);
                continue;
            }

            let mut hasher = Sha256::new();
            // Leaves start at index size-1;
            if node < self.size-1 {
                let c0 = 2 * node + 1;
                let c1 = 2 * node + 2;
                println!("node {} child0={} child1={}", node, c0, c1);

                let child0 = self.tree[c0];
                let child1 = self.tree[c1];
                hasher.update(child0);
                hasher.update(child1);
            } else {
                let leaf = &self.leaves[node+1-self.size];
                hasher.update(leaf);
            }

            let hash = hasher.finalize();
            let hash_array: [u8; 32] = hash.into();
            println!("node {} hash={:x?}", node, hash_array);

            self.tree[node] = hash_array;
            last_update = node;

            // Push parent node to updates.
            if node != 0 {
                self.updates.push_back((node- 1) / 2);
            }
        }


        // Return new root.
        self.tree[0]
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::panic_any;

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

        // Internal tree is double the size of leaves-1.
        assert_eq!(tree.tree.len(), 2*size-1);

        let zero_root_str = "5310a330e8f970388503c73349d80b45cd764db615f1bced2801dcd4524a2ff4";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();

        let root = tree.root();
        assert_eq!(root, zero_root);
    }

    #[test]
    fn alter() {
        let size = 4;
        let mut tree = Tree::new(size).unwrap();
        let zero_root_str = "5310a330e8f970388503c73349d80b45cd764db615f1bced2801dcd4524a2ff4";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();
        let root = tree.root();
        assert_eq!(root, zero_root);

        let new_leaf: Vec<u8> = vec![1,1,1];

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

        let new_leaf: Vec<u8> = vec![1,1,1];
        let new_leaf2: Vec<u8> = vec![2,2,2];

        tree.set_leaf(0, new_leaf);
        tree.set_leaf(3, new_leaf2);
        let new_root = tree.commit();

        let exp_root_str = "afafdad52f016467f2e29867d3adde09133708ba0b4dab04a8cd538b78cc487d";
        let exp_root: [u8; 32] = hex::decode(exp_root_str).unwrap().try_into().unwrap();

        assert_eq!(new_root, exp_root);
    }
}
