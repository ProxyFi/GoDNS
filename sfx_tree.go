package godns

import (
	"strings"
)

// SuffixTreeNode represents a node in the suffix tree.
// It stores a key, an optional value, and a map of children nodes.
type SuffixTreeNode struct {
	// key is the string segment for this node.
	key string
	// value is the value associated with the full path to this node.
	value string
	// children is a map of key segments to child nodes, representing the next level of the tree.
	children map[string]*SuffixTreeNode
}

// NewSuffixTreeRoot creates and returns a new root node for the suffix tree.
// The root node typically has an empty key and value.
func NewSuffixTreeRoot() *SuffixTreeNode {
	return &SuffixTreeNode{
		children: make(map[string]*SuffixTreeNode),
	}
}

// ensureSubTree ensures a child node exists for the given key.
// If the node does not exist, it is created and added to the children map.
func (node *SuffixTreeNode) ensureSubTree(key string) *SuffixTreeNode {
	if child, ok := node.children[key]; ok {
		return child
	}
	
	// Pre-allocating the map for a reasonable size might offer a small performance gain,
	// but a simple make() is often sufficient and more readable.
	newNode := &SuffixTreeNode{
		key:      key,
		children: make(map[string]*SuffixTreeNode),
	}
	node.children[key] = newNode
	return newNode
}

// insert adds or updates a node with a specific key and value.
func (node *SuffixTreeNode) insert(key string, value string) {
	if child, ok := node.children[key]; ok {
		child.value = value
	} else {
		node.children[key] = &SuffixTreeNode{
			key:      key,
			value:    value,
			children: make(map[string]*SuffixTreeNode),
		}
	}
}

// SInsert inserts a sequence of keys (in reverse order, e.g., for a domain name)
// and associates a value with the final key.
// The input `keys` slice is modified within the function, which is a key
// aspect of the original logic. For performance, it avoids creating new slices.
func (node *SuffixTreeNode) SInsert(keys []string, value string) {
	if len(keys) == 0 {
		return
	}

	key := keys[len(keys)-1]
	if len(keys) > 1 {
		child := node.ensureSubTree(key)
		// The recursive call with a sliced array is preserved from the original logic.
		// A potential optimization would be to use an iterative approach to avoid
		// repeated slice creations, but this change preserves the existing logic.
		child.SInsert(keys[:len(keys)-1], value)
		return
	}

	// This is the base case for the recursion.
	node.insert(key, value)
}

// Search searches for a value associated with a sequence of keys.
// The search starts from the longest possible match and falls back to a shorter one.
// This design is specific to the original logic, which prioritizes a longest-suffix match.
func (node *SuffixTreeNode) Search(keys []string) (string, bool) {
	if len(keys) == 0 {
		// A potential match could be at the current node if a value exists.
		// The original logic returns ("", false) here, so we stick to that.
		return "", false
	}

	key := keys[len(keys)-1]
	
	// Check for a child node with the current key.
	if child, ok := node.children[key]; ok {
		// Recursively search the child tree.
		if nextValue, found := child.Search(keys[:len(keys)-1]); found {
			return nextValue, true
		}
		
		// If a full match isn't found further down, check if the current node
		// has a value and return it. This implements the longest-suffix-match behavior.
		if child.value != "" {
			return child.value, true
		}
	}

	// No match found at this level.
	return "", false
}

// SplitDomain splits a domain name string into its components (in reverse order)
// for use with the suffix tree.
// For example, "a.b.c" becomes ["a", "b", "c"].
func SplitDomain(domain string) []string {
	// A simple and efficient way to split by a delimiter.
	// We use `strings.Split` which is well-optimized.
	return strings.Split(domain, ".")
}
