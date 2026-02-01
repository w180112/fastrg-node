#include <stdlib.h>
#include <string.h>

#include "avl_tree.h"

// Helper functions
static inline int max(int a, int b)
{
    return (a > b) ? a : b;
}

static inline int get_height(avl_node_t *node)
{
    return node ? node->height : 0;
}

static inline int get_balance(avl_node_t *node)
{
    return node ? get_height(node->left) - get_height(node->right) : 0;
}

static void update_height(avl_node_t *node)
{
    if (node)
        node->height = 1 + max(get_height(node->left), get_height(node->right));
}

// Rotation functions
static avl_node_t *rotate_right(avl_node_t *y)
{
    avl_node_t *x = y->left;
    avl_node_t *T2 = x->right;

    x->right = y;
    y->left = T2;

    update_height(y);
    update_height(x);

    return x;
}

static avl_node_t *rotate_left(avl_node_t *x)
{
    avl_node_t *y = x->right;
    avl_node_t *T2 = y->left;

    y->left = x;
    x->right = T2;

    update_height(x);
    update_height(y);

    return y;
}

static avl_node_t *balance_node(avl_node_t *node)
{
    if (!node)
        return node;

    update_height(node);
    int balance = get_balance(node);

    // Left-Left case
    if (balance > 1 && get_balance(node->left) >= 0)
        return rotate_right(node);

    // Left-Right case
    if (balance > 1 && get_balance(node->left) < 0) {
        node->left = rotate_left(node->left);
        return rotate_right(node);
    }

    // Right-Right case
    if (balance < -1 && get_balance(node->right) <= 0)
        return rotate_left(node);

    // Right-Left case
    if (balance < -1 && get_balance(node->right) > 0) {
        node->right = rotate_right(node->right);
        return rotate_left(node);
    }

    return node;
}

// Create a new node
static avl_node_t *create_node(void *data)
{
    avl_node_t *node = (avl_node_t *)malloc(sizeof(avl_node_t));
    if (!node)
        return NULL;

    node->data = data;
    node->height = 1;
    node->left = NULL;
    node->right = NULL;

    return node;
}

// Insert helper
static avl_node_t *insert_helper(avl_node_t *node, void *data, avl_compare_fn compare, 
    bool *inserted)
{
    // Standard BST insertion
    if (!node) {
        *inserted = true;
        return create_node(data);
    }

    int cmp = compare(data, node->data);

    if (cmp < 0) {
        node->left = insert_helper(node->left, data, compare, inserted);
    } else if (cmp > 0) {
        node->right = insert_helper(node->right, data, compare, inserted);
    } else {
        // Duplicate - don't insert
        *inserted = false;
        return node;
    }

    // Balance the tree
    return balance_node(node);
}

// Search helper
static void *search_helper(avl_node_t *node, const void *key, avl_compare_fn compare)
{
    if (!node)
        return NULL;

    int cmp = compare(key, node->data);

    if (cmp < 0) {
        return search_helper(node->left, key, compare);
    } else if (cmp > 0) {
        return search_helper(node->right, key, compare);
    } else {
        return node->data;
    }
}

// Find minimum node
static avl_node_t *find_min(avl_node_t *node)
{
    while (node && node->left)
        node = node->left;
    return node;
}

// Delete helper
static avl_node_t *delete_helper(avl_node_t *node, const void *key, avl_compare_fn compare, 
    avl_free_fn free_data, bool *deleted)
{
    if (!node)
        return NULL;

    int cmp = compare(key, node->data);

    if (cmp < 0) {
        node->left = delete_helper(node->left, key, compare, free_data, deleted);
    } else if (cmp > 0) {
        node->right = delete_helper(node->right, key, compare, free_data, deleted);
    } else {
        // Found the node to delete
        *deleted = true;

        // Node with only one child or no child
        if (!node->left || !node->right) {
            avl_node_t *temp = node->left ? node->left : node->right;

            // Free the current node's data
            if (free_data && node->data)
                free_data(node->data);

            if (!temp) {
                // No child case - just delete this node
                free(node);
                return NULL;
            } else {
                // One child case - replace with child
                free(node);
                return temp;
            }
        } else {
            // Node with two children: get the inorder successor
            avl_node_t *temp = find_min(node->right);

            // Copy the inorder successor's data to this node
            if (free_data && node->data)
                free_data(node->data);
            node->data = temp->data;

            // Delete the inorder successor (without freeing its data since we copied it)
            bool dummy = false;
            node->right = delete_helper(node->right, temp->data, compare, NULL, &dummy);
        }
    }

    if (!node)
        return node;

    // Balance the tree
    return balance_node(node);
}

// Free tree helper
static void free_tree_helper(avl_node_t *node, avl_free_fn free_data)
{
    if (!node)
        return;

    free_tree_helper(node->left, free_data);
    free_tree_helper(node->right, free_data);

    if (free_data && node->data)
        free_data(node->data);
    free(node);
}

// Delete if helper
static avl_node_t *delete_if_helper(avl_node_t *node, avl_predicate_fn predicate, 
    void *context, avl_compare_fn compare, avl_free_fn free_data, size_t *count)
{
    if (!node)
        return NULL;

    // Process left and right subtrees first
    node->left = delete_if_helper(node->left, predicate, context, compare, free_data, count);
    node->right = delete_if_helper(node->right, predicate, context, compare, free_data, count);

    // Check if current node matches predicate
    if (predicate(node->data, context)) {
        (*count)++;

        // Delete this node
        if (!node->left || !node->right) {
            avl_node_t *temp = node->left ? node->left : node->right;

            if (free_data && node->data)
                free_data(node->data);
            free(node);

            return temp;
        } else {
            // Node with two children
            avl_node_t *temp = find_min(node->right);

            if (free_data && node->data)
                free_data(node->data);
            node->data = temp->data;

            bool dummy = false;
            node->right = delete_helper(node->right, temp->data, compare, NULL, &dummy);
        }
    }

    if (!node)
        return node;

    // Balance the tree
    return balance_node(node);
}

// Traversal helpers
static void traverse_inorder_helper(avl_node_t *node, avl_visitor_fn visitor, void *context)
{
    if (!node)
        return;

    traverse_inorder_helper(node->left, visitor, context);
    visitor(node->data, context);
    traverse_inorder_helper(node->right, visitor, context);
}

static void traverse_preorder_helper(avl_node_t *node, avl_visitor_fn visitor, void *context)
{
    if (!node)
        return;

    visitor(node->data, context);
    traverse_preorder_helper(node->left, visitor, context);
    traverse_preorder_helper(node->right, visitor, context);
}

static void traverse_postorder_helper(avl_node_t *node, avl_visitor_fn visitor, void *context)
{
    if (!node)
        return;

    traverse_postorder_helper(node->left, visitor, context);
    traverse_postorder_helper(node->right, visitor, context);
    visitor(node->data, context);
}

// Public API implementation

avl_tree_t *avl_tree_create(avl_compare_fn compare, avl_free_fn free_data, 
    avl_copy_fn copy_data)
{
    if (compare == NULL)
        return NULL;

    avl_tree_t *tree = (avl_tree_t *)malloc(sizeof(avl_tree_t));
    if (tree == NULL)
        return NULL;

    tree->root = NULL;
    tree->compare = compare;
    tree->free_data = free_data;
    tree->copy_data = copy_data;
    tree->size = 0;

    return tree;
}

void avl_tree_destroy(avl_tree_t *tree)
{
    if (!tree)
        return;

    free_tree_helper(tree->root, tree->free_data);
    free(tree);
}

bool avl_tree_insert(avl_tree_t *tree, void *data)
{
    if (!tree || !data)
        return false;

    void *data_to_insert = data;

    // If copy function provided, copy the data
    if (tree->copy_data) {
        data_to_insert = tree->copy_data(data);
        if (!data_to_insert)
            return false;
    }

    bool inserted = false;
    tree->root = insert_helper(tree->root, data_to_insert, tree->compare, &inserted);

    if (inserted) {
        tree->size++;
        return true;
    } else {
        // If not inserted and we copied the data, free it
        if (tree->copy_data && tree->free_data)
            tree->free_data(data_to_insert);
        return false;
    }
}

void *avl_tree_search(const avl_tree_t *tree, const void *key)
{
    if (!tree || !key)
        return NULL;

    return search_helper(tree->root, key, tree->compare);
}

bool avl_tree_delete(avl_tree_t *tree, const void *key)
{
    if (!tree || !key)
        return false;

    bool deleted = false;
    tree->root = delete_helper(tree->root, key, tree->compare, tree->free_data, &deleted);

    if (deleted)
        tree->size--;

    return deleted;
}

size_t avl_tree_delete_if(avl_tree_t *tree, avl_predicate_fn predicate, void *context)
{
    if (!tree || !predicate)
        return 0;

    size_t count = 0;
    tree->root = delete_if_helper(tree->root, predicate, context, tree->compare, 
                                   tree->free_data, &count);
    tree->size -= count;

    return count;
}

size_t avl_tree_size(const avl_tree_t *tree)
{
    return tree ? tree->size : 0;
}

bool avl_tree_is_empty(const avl_tree_t *tree)
{
    return tree ? (tree->size == 0) : true;
}

void avl_tree_clear(avl_tree_t *tree)
{
    if (!tree)
        return;

    free_tree_helper(tree->root, tree->free_data);
    tree->root = NULL;
    tree->size = 0;
}

void avl_tree_traverse_inorder(const avl_tree_t *tree, avl_visitor_fn visitor, 
    void *context)
{
    if (!tree || !visitor)
        return;

    traverse_inorder_helper(tree->root, visitor, context);
}

void avl_tree_traverse_preorder(const avl_tree_t *tree, avl_visitor_fn visitor, 
    void *context) 
{
    if (!tree || !visitor)
        return;

    traverse_preorder_helper(tree->root, visitor, context);
}

void avl_tree_traverse_postorder(const avl_tree_t *tree, avl_visitor_fn visitor, 
    void *context)
{
    if (!tree || !visitor)
        return;

    traverse_postorder_helper(tree->root, visitor, context);
}

int avl_tree_height(const avl_tree_t *tree)
{
    return tree ? get_height(tree->root) : 0;
}
