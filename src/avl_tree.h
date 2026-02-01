#ifndef AVL_TREE_H
#define AVL_TREE_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Generic AVL Tree Implementation
 * 
 * This is a self-balancing binary search tree that can store any type of data.
 * Users must provide comparison and optional cleanup functions.
 */

// Forward declarations
typedef struct avl_node avl_node_t;
typedef struct avl_tree avl_tree_t;

/**
 * Comparison function type
 * Should return:
 *   < 0 if data1 < data2
 *   = 0 if data1 == data2
 *   > 0 if data1 > data2
 */
typedef int (*avl_compare_fn)(const void *data1, const void *data2);

/**
 * Data cleanup function type
 * Called when a node is being deleted
 * Use this to free any memory allocated for your data
 */
typedef void (*avl_free_fn)(void *data);

/**
 * Data copy function type (optional)
 * Called when data needs to be duplicated
 * If NULL, tree will store the pointer directly without copying
 */
typedef void *(*avl_copy_fn)(const void *data);

/**
 * Predicate function for conditional operations
 * Should return true if the condition is met
 */
typedef bool (*avl_predicate_fn)(const void *data, void *context);

/**
 * Visitor function for tree traversal
 * Called for each node during traversal
 */
typedef void (*avl_visitor_fn)(void *data, void *context);

// AVL tree node structure
struct avl_node {
    void *data;              // Pointer to user data
    int height;              // Node height for balancing
    avl_node_t *left;        // Left child
    avl_node_t *right;       // Right child
};

// AVL tree structure
struct avl_tree {
    avl_node_t *root;        // Root node
    avl_compare_fn compare;  // Comparison function
    avl_free_fn free_data;   // Data cleanup function (can be NULL)
    avl_copy_fn copy_data;   // Data copy function (can be NULL)
    size_t size;             // Number of nodes in the tree
};

/**
 * @fn avl_tree_create
 * 
 * @brief Create a new AVL tree
 * 
 * @param compare 
 *      Comparison function (required)
 * @param free_data 
 *      Data cleanup function (optional, can be NULL)
 * @param copy_data 
 *      Data copy function (optional, can be NULL)
 * @return 
 *      Pointer to new tree, or NULL on failure
 */
avl_tree_t *avl_tree_create(avl_compare_fn compare, avl_free_fn free_data, avl_copy_fn copy_data);

/**
 * @fn avl_tree_destroy
 * 
 * @brief Destroy the tree and free all memory
 * 
 * @param tree 
 *      Pointer to tree
 * @return
 *      void
 */
void avl_tree_destroy(avl_tree_t *tree);

/**
 * @fn avl_tree_insert
 * 
 * @brief Insert data into the tree
 * 
 * @param tree 
 *      Pointer to tree
 * @param data 
 *      Data to insert
 * @return 
 *      true on success, false on failure
 */
bool avl_tree_insert(avl_tree_t *tree, void *data);

/**
 * @fn avl_tree_search
 * 
 * @brief Search for data in the tree
 * 
 * @param tree Pointer to tree
 * @param key Key to search for (compared using compare function)
 * @return Pointer to data if found, NULL otherwise
 */
void *avl_tree_search(const avl_tree_t *tree, const void *key);

/**
 * @fn avl_tree_delete
 * 
 * @brief Delete data from the tree
 * 
 * @param tree 
 *      Pointer to tree
 * @param key 
 *      Key to delete
 * @return 
 *      true if deleted, false if not found
 */
bool avl_tree_delete(avl_tree_t *tree, const void *key);

/**
 * @fn avl_tree_delete_if
 * 
 * @brief Delete all nodes that match a predicate
 * 
 * @param tree 
 *      Pointer to tree
 * @param predicate 
 *      Predicate function
 * @param context 
 *      Context passed to predicate
 * @return 
 *      Number of nodes deleted
 */
size_t avl_tree_delete_if(avl_tree_t *tree, avl_predicate_fn predicate, void *context);

/**
 * @fn avl_tree_size
 * 
 * @brief Get the number of nodes in the tree
 * 
 * @param tree 
 *      Pointer to tree
 * @return 
 *      Number of nodes
 */
size_t avl_tree_size(const avl_tree_t *tree);

/**
 * @fn avl_tree_is_empty
 * 
 * @brief Check if the tree is empty
 * 
 * @param tree 
 *      Pointer to tree
 * @return 
 *      true if empty, false otherwise
 */
bool avl_tree_is_empty(const avl_tree_t *tree);

/**
 * @fn avl_tree_clear
 * 
 * @brief Clear all nodes from the tree
 * 
 * @param tree 
 *      Pointer to tree
 * @return
 *      void
 */
void avl_tree_clear(avl_tree_t *tree);

/**
 * @fn avl_tree_traverse_inorder
 * 
 * @brief Traverse the tree in-order and apply visitor function
 * 
 * @param tree 
 *      Pointer to tree
 * @param visitor 
 *      Visitor function
 * @param context 
 *      Context passed to visitor
 * @return
 *      void
 */
void avl_tree_traverse_inorder(const avl_tree_t *tree, avl_visitor_fn visitor, void *context);

/**
 * @fn avl_tree_traverse_preorder
 * 
 * @brief Traverse the tree pre-order and apply visitor function
 * 
 * @param tree 
 *      Pointer to tree
 * @param visitor 
 *      Visitor function
 * @param context 
 *      Context passed to visitor
 * @return
 *      void
 */
void avl_tree_traverse_preorder(const avl_tree_t *tree, avl_visitor_fn visitor, void *context);

/**
 * @fn avl_tree_traverse_postorder
 * 
 * @brief Traverse the tree post-order and apply visitor function
 * 
 * @param tree 
 *      Pointer to tree
 * @param visitor 
 *      Visitor function
 * @param context 
 *      Context passed to visitor
 * @return
 *      void
 */
void avl_tree_traverse_postorder(const avl_tree_t *tree, avl_visitor_fn visitor, void *context);

/**
 * @fn avl_tree_height
 * 
 * @brief Get the height of the tree
 * 
 * @param tree 
 *      Pointer to tree
 * @return 
 *      Height of the tree
 */
int avl_tree_height(const avl_tree_t *tree);

#endif // AVL_TREE_H
