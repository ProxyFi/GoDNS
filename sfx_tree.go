package godns

// suffixTreeNode represents a node in the suffix tree.
// The key is a single part of a domain name (e.g., "com", "google").
// The value stores the associated data for this node, if it's a complete entry.
// The children map holds the sub-nodes for the next part of the domain.
type suffixTreeNode struct {
	key      string
	value    string
	children map[string]*suffixTreeNode
}

// newSuffixTreeRoot creates and returns a new root node for the suffix tree.
// The root node has an empty key and value.
func newSuffixTreeRoot() *suffixTreeNode {
	return &suffixTreeNode{
		key:      "",
		value:    "",
		children: make(map[string]*suffixTreeNode),
	}
}

// ensureSubTree checks if a child node with the given key exists.
// If it doesn't, a new empty node is created and added to the children map.
func (node *suffixTreeNode) ensureSubTree(key string) {
	if _, ok := node.children[key]; !ok {
		node.children[key] = &suffixTreeNode{
			key:      key,
			value:    "",
			children: make(map[string]*suffixTreeNode),
		}
	}
}

// InsertDomain inserts a new key-value pair into the suffix tree.
// It takes a slice of domain parts (keys) and the associated value.
// The keys slice is processed from right to left (TLD to subdomain).
func (node *suffixTreeNode) InsertDomain(keys []string, value string) {
	// Start with the root node.
	currentNode := node
	// Iterate over the keys in reverse order to build the tree from the TLD.
	for i := len(keys) - 1; i >= 0; i-- {
		key := keys[i]
		currentNode.ensureSubTree(key)
		currentNode = currentNode.children[key]
	}
	// Once we're at the final node, set its value.
	currentNode.value = value
}

// SearchDomain searches for a value associated with a slice of domain parts.
// It returns the found value and a boolean indicating success.
// It follows the domain parts from right to left (TLD to subdomain).
// This function is now iterative, avoiding potential stack overflow issues.
func (node *suffixTreeNode) SearchDomain(keys []string) (string, bool) {
	currentNode := node
	var bestMatchValue string

	// Iterate over the keys in reverse order.
	for i := len(keys) - 1; i >= 0; i-- {
		key := keys[i]
		// Check if the current key exists in the children map.
		if nextNode, ok := currentNode.children[key]; ok {
			currentNode = nextNode
			// If a value exists at this level, it's the current best match.
			if currentNode.value != "" {
				bestMatchValue = currentNode.value
			}
		} else {
			// If a key is not found, we can't continue the specific path.
			// Return the best value found so far.
			return bestMatchValue, bestMatchValue != ""
		}
	}

	// After iterating through all keys, the last found value is the most specific.
	return currentNode.value, currentNode.value != ""
}

// Delete removes a key-value pair from the suffix tree.
// It traverses the tree and removes the specified value.
func (node *suffixTreeNode) Delete(keys []string) {
	// Start with the root node.
	currentNode := node
	var path []*suffixTreeNode

	// Traverse the tree to find the node to be deleted.
	// Store the path to the node for potential cleanup.
	for i := len(keys) - 1; i >= 0; i-- {
		key := keys[i]
		if _, ok := currentNode.children[key]; !ok {
			return // Key not found, nothing to delete.
		}
		path = append(path, currentNode)
		currentNode = currentNode.children[key]
	}
	
	// Found the node, so clear its value.
	currentNode.value = ""

	// Now, clean up the tree by removing any nodes that have no value and no children.
	for i := len(path) - 1; i >= 0; i-- {
		parent := path[i]
		childKey := keys[len(keys)-1-i]
		childNode := parent.children[childKey]

		// Check if the child node is a leaf (no value and no children).
		if childNode.value == "" && len(childNode.children) == 0 {
			delete(parent.children, childKey)
		} else {
			// Stop cleanup if we hit a node that's part of another domain.
			break
		}
	}
}
