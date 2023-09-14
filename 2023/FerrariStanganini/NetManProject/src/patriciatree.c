#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "roaring.c"

struct Result {
    uint32_t ip;
    roaring_bitmap_t *ports;
};

struct Node {
    int leaf;
    struct Node *left;
    struct Node *right;
    roaring_bitmap_t *ports;
};
 
struct Node* createNode() {
    struct Node* newNode = (struct Node*)malloc(sizeof(struct Node));
    if (newNode != NULL) {
        newNode->leaf = 0;
        newNode->left = NULL;
        newNode->right = NULL;
        newNode->ports = roaring_bitmap_create();
    }
    return newNode;
}

int insert(struct Node* root, uint32_t ip,int total) {
    struct Node* currentNode = root;
    for (int i = 31; i >= 0; i--) {
        int bit = (ip >> i) & 1;
        if (bit == 0) {
            if (currentNode->left == NULL) {
                currentNode->left = createNode();
            }
            currentNode = currentNode->left;
        } else {
            if (currentNode->right == NULL) {
                currentNode->right = createNode();
            }
            currentNode = currentNode->right;
        }
    }
    currentNode->leaf = 1;
    return ++total;
}

roaring_bitmap_t* search(struct Node* root, uint32_t ip) {
    struct Node* currentNode = root;
    for (int i = 31; i >= 0; i--) {
        int bit = (ip >> i) & 1;
        if (bit == 0) {
            if (currentNode->left == NULL) {
                return NULL; 
            }
            currentNode = currentNode->left;
        } else {
            if (currentNode->right == NULL) {
                return NULL; 
            }
            currentNode = currentNode->right;
        }
    }
    if (currentNode->leaf) {
        return currentNode->ports; 
    } else {
        return NULL; 
    }
}

bool iter(uint32_t value, void* p)
{
    printf(" %u ",value);
    return true;
}

int z = 0;
void traverse(struct Node* node, uint32_t ip, int level, struct Result* res) {
    if (node == NULL) {
        return;
    }

    if (node->leaf) {
        //res[z] = malloc(sizeof(struct Result));
        res[z].ip = ip;
        res[z].ports = node->ports;
        z = z+1;
    }

    traverse(node->left, ip << 1, level + 1, res);
    traverse(node->right, (ip << 1) | 1, level + 1, res);
}

struct Result* traverseTree(struct Node* root,int total) {
    z = 0;
    struct Result* res = calloc(total,sizeof(struct Result));   
    traverse(root, 0, 0, res);
    return res;
}

void traverseFree(struct Node* node, uint32_t ip, int level, struct Node** res) {
    if (node == NULL) {
        return;
    }

    if (node->leaf) {
        res[z] = node;
        z = z+1;
    }

    traverseFree(node->left, ip << 1, level + 1, res);
    traverseFree(node->right, (ip << 1) | 1, level + 1, res);

    if ((!(node->leaf))&&(!(node == NULL))){
        roaring_bitmap_free(node->ports);
        free(node);
    }

}


void freePatricia(struct Node* root,int total) {
    z = 0;
    struct Node** res = calloc(total,sizeof(struct Node*));   
    traverseFree(root, 0, 0, res);
    for (int i=0; i<total; i++) {
        roaring_bitmap_free(res[i]->ports);
        free(res[i]);
    }
    free(res);
}
