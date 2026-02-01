
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>

#include <common.h>

#include "../src/fastrg.h"
#include "../src/avl_tree.h"
#include "test_helper.h"

// Test data structures
typedef struct {
    int id;
    char name[50];
} test_record_t;

typedef struct {
    int value;
} simple_int_t;

// Global test counters
static int test_count = 0;
static int pass_count = 0;

// Comparison functions for different types
static int compare_ints(const void *a, const void *b) {
    const simple_int_t *ia = (const simple_int_t *)a;
    const simple_int_t *ib = (const simple_int_t *)b;
    return ia->value - ib->value;
}

static int compare_strings(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int compare_records(const void *a, const void *b) {
    const test_record_t *ra = (const test_record_t *)a;
    const test_record_t *rb = (const test_record_t *)b;
    return ra->id - rb->id;
}

// Copy functions
static void* copy_string(const void *data) {
    return strdup((const char *)data);
}

// Visitor function for traversal
static void visitor_fn(void *data, void *context) {
    int *count = (int *)context;
    (*count)++;
}

// Predicate function for conditional delete
static bool is_even(const void *data, void *context) {
    const simple_int_t *val = (const simple_int_t *)data;
    return (val->value % 2) == 0;
}

static bool is_greater_than(const void *data, void *context) {
    const simple_int_t *val = (const simple_int_t *)data;
    int threshold = *(int *)context;
    return val->value > threshold;
}

// Test 1: Basic tree creation and destruction
void test_tree_create_destroy() {
    printf("\nTest 1: Tree Creation and Destruction\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);
    TEST_ASSERT(tree != NULL, "Create tree", "tree is NULL");
    TEST_ASSERT(avl_tree_is_empty(tree), "New tree is empty", "tree is not empty");
    TEST_ASSERT(avl_tree_size(tree) == 0, "New tree has size 0", "size is not 0");
    TEST_ASSERT(avl_tree_height(tree) == 0, "New tree has height 0", "height is not 0");

    avl_tree_destroy(tree);
    printf("  ✓ Tree destroyed successfully\n");
}

// Test 2: Insert and search operations
void test_insert_search() {
    printf("\nTest 2: Insert and Search Operations\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    // Insert values
    int values[] = {50, 30, 70, 20, 40, 60, 80};
    int n = sizeof(values) / sizeof(values[0]);

    for(int i=0; i<n; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = values[i];
        bool inserted = avl_tree_insert(tree, val);
        TEST_ASSERT(inserted, "Insert value", "failed to insert %d", values[i]);
    }

    TEST_ASSERT(avl_tree_size(tree) == n, "Tree size after inserts", 
        "size is %zu, expected %d", avl_tree_size(tree), n);
    TEST_ASSERT(!avl_tree_is_empty(tree), "Tree is not empty", "tree is empty");
    // Search for existing values
    for(int i=0; i<n; i++) {
        simple_int_t search_key = { .value = values[i] };
        simple_int_t *found = avl_tree_search(tree, &search_key);
        TEST_ASSERT(found != NULL && found->value == values[i], "Search existing value", 
            "expected %d, got %d", values[i], found ? found->value : -1);
    }

    // Search for non-existing value
    simple_int_t search_key = { .value = 999 };
    simple_int_t *not_found = avl_tree_search(tree, &search_key);
    TEST_ASSERT(not_found == NULL, "Search non-existing value returns NULL", 
        "expected NULL, got %d", not_found ? not_found->value : -1);

    avl_tree_destroy(tree);
}

// Test 3: Delete operations
void test_delete() {
    printf("\nTest 3: Delete Operations\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    // Insert values
    int values[] = {50, 30, 70, 20, 40, 60, 80, 10, 25, 35, 45};
    int n = sizeof(values) / sizeof(values[0]);

    for(int i=0; i<n; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = values[i];
        avl_tree_insert(tree, val);
    }

    size_t initial_size = avl_tree_size(tree);
    TEST_ASSERT(initial_size == n, "Initial tree size", 
        "size is %zu, expected %d", initial_size, n);

    // Delete leaf node
    simple_int_t key1 = { .value = 10 };
    bool deleted1 = avl_tree_delete(tree, &key1);
    TEST_ASSERT(deleted1, "Delete leaf node", "failed to delete %d", key1.value);
    TEST_ASSERT(avl_tree_size(tree) == initial_size - 1, "Size after delete leaf", 
        "size is %zu, expected %zu", avl_tree_size(tree), initial_size - 1);

    // Delete node with one child
    simple_int_t key2 = { .value = 20 };
    bool deleted2 = avl_tree_delete(tree, &key2);
    TEST_ASSERT(deleted2, "Delete node with one child", "failed to delete %d", key2.value);
    TEST_ASSERT(avl_tree_size(tree) == initial_size - 2, "Size after delete one child", 
        "size is %zu, expected %zu", avl_tree_size(tree), initial_size - 2);

    // Delete node with two children
    simple_int_t key3 = { .value = 30 };
    bool deleted3 = avl_tree_delete(tree, &key3);
    TEST_ASSERT(deleted3, "Delete node with two children", "failed to delete %d", key3.value);
    TEST_ASSERT(avl_tree_size(tree) == initial_size - 3, "Size after delete two children", 
        "size is %zu, expected %zu", avl_tree_size(tree), initial_size - 3);

    // Delete non-existing node
    simple_int_t key4 = { .value = 999 };
    bool deleted4 = avl_tree_delete(tree, &key4);
    TEST_ASSERT(!deleted4, "Delete non-existing node returns false", 
        "unexpectedly deleted %d", key4.value);
    TEST_ASSERT(avl_tree_size(tree) == initial_size - 3, 
        "Size unchanged after failed delete", "size is %zu, expected %zu", 
        avl_tree_size(tree), initial_size - 3);

    avl_tree_destroy(tree);
}

// Test 4: Tree balancing
void test_balancing() {
    printf("\nTest 4: Tree Balancing\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    // Insert values in ascending order (would create unbalanced tree without AVL)
    int n = 15;
    for(int i=1; i<=n; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = i;
        avl_tree_insert(tree, val);
    }

    int height = avl_tree_height(tree);
    int max_balanced_height = (int)(1.44 * log2(n + 2));  // AVL height bound

    printf("  Tree with %d nodes has height %d (max balanced: %d)\n", n, height, max_balanced_height);
    TEST_ASSERT(height <= max_balanced_height, "Tree is balanced", 
        "height %d exceeds max balanced %d", height, max_balanced_height);

    // Insert in descending order
    avl_tree_clear(tree);
    for(int i=n; i>=1; i--) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = i;
        avl_tree_insert(tree, val);
    }

    height = avl_tree_height(tree);
    printf("  Tree with descending inserts has height %d (max balanced: %d)\n", height, max_balanced_height);
    TEST_ASSERT(height <= max_balanced_height, "Tree balanced after descending inserts", 
        "height %d exceeds max balanced %d", height, max_balanced_height);

    avl_tree_destroy(tree);
}

// Test 5: Duplicate insertion
void test_duplicates() {
    printf("\nTest 5: Duplicate Insertion\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    simple_int_t *val1 = malloc(sizeof(simple_int_t));
    val1->value = 42;
    bool inserted1 = avl_tree_insert(tree, val1);
    TEST_ASSERT(inserted1, "Insert first value", "failed to insert %d", val1->value);
    TEST_ASSERT(avl_tree_size(tree) == 1, "Size is 1 after first insert", 
        "size is %zu", avl_tree_size(tree));

    simple_int_t *val2 = malloc(sizeof(simple_int_t));
    val2->value = 42;
    bool inserted2 = avl_tree_insert(tree, val2);
    TEST_ASSERT(!inserted2, "Duplicate insert returns false", 
        "unexpectedly inserted duplicate %d", val2->value);
    TEST_ASSERT(avl_tree_size(tree) == 1, "Size unchanged after duplicate insert", 
        "size is %zu", avl_tree_size(tree));

    // The duplicate wasn't inserted, so we need to free it
    free(val2);

    avl_tree_destroy(tree);
}

// Test 6: Clear operation
void test_clear() {
    printf("\nTest 6: Clear Operation\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    // Insert values
    for(int i=1; i<=10; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = i * 10;
        avl_tree_insert(tree, val);
    }

    TEST_ASSERT(avl_tree_size(tree) == 10, "Tree has 10 elements", 
        "size is %zu", avl_tree_size(tree));
    TEST_ASSERT(!avl_tree_is_empty(tree), "Tree is not empty", "tree is empty");

    avl_tree_clear(tree);

    TEST_ASSERT(avl_tree_size(tree) == 0, "Tree size is 0 after clear", 
        "size is %zu", avl_tree_size(tree));
    TEST_ASSERT(avl_tree_is_empty(tree), "Tree is empty after clear", 
        "tree is not empty");
    TEST_ASSERT(avl_tree_height(tree) == 0, "Tree height is 0 after clear", 
        "height is %d", avl_tree_height(tree));

    avl_tree_destroy(tree);
}

// Test 7: Traversal operations
void test_traversal() {
    printf("\nTest 7: Traversal Operations\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    // Insert values: 50, 30, 70, 20, 40, 60, 80
    int values[] = {50, 30, 70, 20, 40, 60, 80};
    int n = sizeof(values) / sizeof(values[0]);

    for(int i=0; i<n; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = values[i];
        avl_tree_insert(tree, val);
    }

    int count_inorder = 0;
    avl_tree_traverse_inorder(tree, visitor_fn, &count_inorder);
    TEST_ASSERT(count_inorder == n, "Inorder traversal visits all nodes", 
        "visited %d, expected %d", count_inorder, n);

    int count_preorder = 0;
    avl_tree_traverse_preorder(tree, visitor_fn, &count_preorder);
    TEST_ASSERT(count_preorder == n, "Preorder traversal visits all nodes", 
        "visited %d, expected %d", count_preorder, n);

    int count_postorder = 0;
    avl_tree_traverse_postorder(tree, visitor_fn, &count_postorder);
    TEST_ASSERT(count_postorder == n, "Postorder traversal visits all nodes", 
        "visited %d, expected %d", count_postorder, n);
    avl_tree_destroy(tree);
}

// Test 8: Conditional delete (delete_if)
void test_delete_if() {
    printf("\nTest 8: Conditional Delete (delete_if)\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    // Insert values 1 to 10
    for(int i=1; i<=10; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = i;
        avl_tree_insert(tree, val);
    }

    TEST_ASSERT(avl_tree_size(tree) == 10, "Tree has 10 elements", 
        "size is %zu", avl_tree_size(tree));

    // Delete all even numbers
    size_t deleted = avl_tree_delete_if(tree, is_even, NULL);
    TEST_ASSERT(deleted == 5, "Deleted 5 even numbers", "deleted %zu", deleted);
    TEST_ASSERT(avl_tree_size(tree) == 5, "Tree has 5 elements after delete_if", 
        "size is %zu", avl_tree_size(tree));

    // Verify only odd numbers remain
    for(int i=1; i<=10; i++) {
        simple_int_t search_key = { .value = i };
        simple_int_t *found = avl_tree_search(tree, &search_key);
        if (i % 2 == 1) {
            TEST_ASSERT(found != NULL, "Odd number still in tree", 
                "odd number %d not found", i);
        } else {
            TEST_ASSERT(found == NULL, "Even number removed from tree", 
                "even number %d found", i);
        }
    }

    avl_tree_destroy(tree);
}

// Test 9: String tree with copy function
void test_string_tree() {
    printf("\nTest 9: String Tree with Copy Function\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_strings, free, copy_string);

    // Insert strings (will be copied)
    const char *words[] = {"banana", "apple", "cherry", "date", "elderberry"};
    int n = sizeof(words) / sizeof(words[0]);

    for(int i=0; i<n; i++) {
        bool inserted = avl_tree_insert(tree, (void*)words[i]);
        TEST_ASSERT(inserted, "Insert string", "failed to insert %s", words[i]);
    }

    TEST_ASSERT(avl_tree_size(tree) == n, "Tree has all strings", 
        "size is %zu, expected %d", avl_tree_size(tree), n);

    // Search for strings
    char *found_apple = avl_tree_search(tree, "apple");
    TEST_ASSERT(found_apple != NULL && strcmp(found_apple, "apple") == 0, 
        "Search 'apple'", "got %s", found_apple ? found_apple : "NULL");

    char *found_grape = avl_tree_search(tree, "grape");
    TEST_ASSERT(found_grape == NULL, "Search non-existing 'grape'", 
        "got %s", found_grape ? found_grape : "NULL");

    // Delete a string
    bool deleted = avl_tree_delete(tree, "cherry");
    TEST_ASSERT(deleted, "Delete 'cherry'", "failed to delete 'cherry'");
    TEST_ASSERT(avl_tree_size(tree) == n - 1, "Size after delete", 
        "size is %zu, expected %d", avl_tree_size(tree), n - 1);

    // Count traversal
    int count = 0;
    avl_tree_traverse_inorder(tree, visitor_fn, &count);
    TEST_ASSERT(count == n - 1, "Traversal counts correct number", 
        "counted %d, expected %d", count, n - 1);

    avl_tree_destroy(tree);
}

// Test 10: Complex struct tree
void test_struct_tree() {
    printf("\nTest 10: Complex Struct Tree\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_records, free, NULL);

    // Insert records
    int ids[] = {100, 50, 150, 25, 75, 125, 175};
    int n = sizeof(ids) / sizeof(ids[0]);

    for(int i=0; i<n; i++) {
        test_record_t *rec = malloc(sizeof(test_record_t));
        rec->id = ids[i];
        snprintf(rec->name, sizeof(rec->name), "Record_%d", ids[i]);
        avl_tree_insert(tree, rec);
    }

    TEST_ASSERT(avl_tree_size(tree) == n, "Tree has all records", 
        "size is %zu, expected %d", avl_tree_size(tree), n);

    // Search for record
    test_record_t search_key = { .id = 75 };
    test_record_t *found = avl_tree_search(tree, &search_key);
    TEST_ASSERT(found != NULL && found->id == 75, "Search record by id", 
        "expected id 75, got %d", found ? found->id : -1);
    TEST_ASSERT(strcmp(found->name, "Record_75") == 0, "Record has correct name", 
        "expected 'Record_75', got '%s'", found ? found->name : "NULL");

    // Delete record
    test_record_t delete_key = { .id = 150 };
    bool deleted = avl_tree_delete(tree, &delete_key);
    TEST_ASSERT(deleted, "Delete record", "failed to delete id %d", delete_key.id);
    TEST_ASSERT(avl_tree_size(tree) == n - 1, "Size after delete record", 
        "size is %zu, expected %d", avl_tree_size(tree), n - 1);

    avl_tree_destroy(tree);
}

// Test 11: Large tree stress test
void test_large_tree() {
    printf("\nTest 11: Large Tree Stress Test\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    int n = 1000;
    printf("  Inserting %d elements...\n", n);

    // Insert random values
    srand(42);  // Fixed seed for reproducibility
    for(int i=0; i<n; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = rand() % 10000;
        avl_tree_insert(tree, val);
    }

    size_t size = avl_tree_size(tree);
    int height = avl_tree_height(tree);
    int max_height = (int)(1.44 * log2(size + 2));

    printf("  Tree size: %zu, height: %d (max balanced: %d)\n", size, height, max_height);
    TEST_ASSERT(size <= n, "Tree size is reasonable (accounting for duplicates)", 
        "size is %zu, expected <= %d", size, n);
    TEST_ASSERT(height <= max_height, "Large tree is balanced", 
        "height %d exceeds max balanced %d", height, max_height);

    // Delete half the elements
    printf("  Deleting elements...\n");
    int deleted_count = 0;
    for(int i=0; i<5000; i+=10) {
        simple_int_t key = { .value = i };
        if (avl_tree_delete(tree, &key)) {
            deleted_count++;
        }
    }
    printf("  Deleted %d elements\n", deleted_count);

    height = avl_tree_height(tree);
    size = avl_tree_size(tree);
    max_height = (int)(1.44 * log2(size + 2));
    printf("  Tree size after deletes: %zu, height: %d (max balanced: %d)\n", size, height, max_height);
    TEST_ASSERT(height <= max_height, "Tree balanced after deletes", 
        "height %d exceeds max balanced %d", height, max_height);

    avl_tree_destroy(tree);
}

// Test 12: Edge cases
void test_edge_cases() {
    printf("\nTest 12: Edge Cases\n");
    printf("=========================================\n");

    // Test NULL tree operations
    TEST_ASSERT(avl_tree_size(NULL) == 0, "Size of NULL tree is 0", 
        "got size %zu", avl_tree_size(NULL));
    TEST_ASSERT(avl_tree_is_empty(NULL) == true, "NULL tree is empty", 
        "got is not empty");
    TEST_ASSERT(avl_tree_height(NULL) == 0, "Height of NULL tree is 0", 
        "got height %d", avl_tree_height(NULL));
    TEST_ASSERT(avl_tree_search(NULL, NULL) == NULL, "Search in NULL tree returns NULL", 
        "got non-NULL result");
    TEST_ASSERT(avl_tree_delete(NULL, NULL) == false, "Delete from NULL tree returns false", 
        "got true");

    // Test insert NULL data
    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);
    TEST_ASSERT(!avl_tree_insert(tree, NULL), "Insert NULL data returns false", 
        "got true");

    // Test single element tree
    simple_int_t *val = malloc(sizeof(simple_int_t));
    val->value = 42;
    avl_tree_insert(tree, val);
    TEST_ASSERT(avl_tree_size(tree) == 1, "Single element tree size", 
        "size is %zu", avl_tree_size(tree));
    TEST_ASSERT(avl_tree_height(tree) == 1, "Single element tree height", 
        "height is %d", avl_tree_height(tree));

    simple_int_t key = { .value = 42 };
    avl_tree_delete(tree, &key);
    TEST_ASSERT(avl_tree_is_empty(tree), "Tree empty after deleting single element", 
        "tree is not empty");

    avl_tree_destroy(tree);
}

// Test 13: Delete if with context
void test_delete_if_with_context() {
    printf("\nTest 13: Delete If with Context\n");
    printf("=========================================\n");

    avl_tree_t *tree = avl_tree_create(compare_ints, free, NULL);

    // Insert values 1 to 20
    for(int i=1; i<=20; i++) {
        simple_int_t *val = malloc(sizeof(simple_int_t));
        val->value = i;
        avl_tree_insert(tree, val);
    }

    // Delete all values greater than 10
    int threshold = 10;
    size_t deleted = avl_tree_delete_if(tree, is_greater_than, &threshold);
    TEST_ASSERT(deleted == 10, "Deleted 10 values greater than 10", 
        "deleted %zu", deleted);
    TEST_ASSERT(avl_tree_size(tree) == 10, "Tree has 10 elements remaining", 
        "size is %zu", avl_tree_size(tree));

    // Verify values <= 10 remain
    for(int i=1; i<=10; i++) {
        simple_int_t key = { .value = i };
        TEST_ASSERT(avl_tree_search(tree, &key) != NULL, "Value <= 10 still in tree", 
            "value %d not found", i);
    }

    // Verify values > 10 are gone
    for(int i=11; i<=20; i++) {
        simple_int_t key = { .value = i };
        TEST_ASSERT(avl_tree_search(tree, &key) == NULL, "Value > 10 removed from tree", 
            "value %d found", i);
    }

    avl_tree_destroy(tree);
}

// Main test runner
void test_avl_tree(FastRG_t *fastrg_ccb, U32 *total_tests, U32 *total_pass)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║           AVL Tree Unit Tests                              ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    test_count = 0;
    pass_count = 0;

    test_tree_create_destroy();
    test_insert_search();
    test_delete();
    test_balancing();
    test_duplicates();
    test_clear();
    test_traversal();
    test_delete_if();
    test_string_tree();
    test_struct_tree();
    test_large_tree();
    test_edge_cases();
    test_delete_if_with_context();

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                              ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:  %3d                                         ║\n", test_count);
    printf("║  Passed:       %3d                                         ║\n", pass_count);
    printf("║  Failed:       %3d                                         ║\n", test_count - pass_count);
    printf("║  Success Rate: %3d%%                                        ║\n", 
           test_count > 0 ? (pass_count * 100 / test_count) : 0);
    printf("╚════════════════════════════════════════════════════════════╝\n");

    if (pass_count == test_count) {
        printf("\n✓ All tests passed!\n");
    } else {
        printf("\n✗ Some tests failed!\n");
    }

    *total_tests += test_count;
    *total_pass += pass_count;
}