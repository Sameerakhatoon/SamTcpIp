#include <stdlib.h>
#include "glthread.h"

// Forward declarations (top-of-file convention).
static void noop_unused(void);

void         init_glthread(GlThread* gl);
void         glthread_add_next(GlThread* curr, GlThread* new_gl);
void         glthread_add_before(GlThread* curr, GlThread* new_gl);
void         remove_glthread(GlThread* curr);
void         glthread_add_last(GlThread* base, GlThread* new_gl);
void         delete_glthread_list(GlThread* base);
unsigned int get_glthread_list_count(GlThread* base);
void         glthread_priority_insert(GlThread* base, GlThread* new_gl,
                                      int (*comp_fn)(void*, void*),
                                      int offset);

static void noop_unused(void){
    // Silences picky linters when this TU has no static functions.
}

void init_glthread(GlThread* gl){
    gl->left  = 0;
    gl->right = 0;
}

// Splice new_gl in immediately after curr.
void glthread_add_next(GlThread* curr, GlThread* new_gl){
    if(!curr->right){
        curr->right    = new_gl;
        new_gl->left   = curr;
        return;
    }
    GlThread* tmp  = curr->right;
    curr->right    = new_gl;
    new_gl->left   = curr;
    new_gl->right  = tmp;
    tmp->left      = new_gl;
}

void glthread_add_before(GlThread* curr, GlThread* new_gl){
    if(!curr->left){
        new_gl->left  = 0;
        new_gl->right = curr;
        curr->left    = new_gl;
        return;
    }
    GlThread* tmp = curr->left;
    tmp->right    = new_gl;
    new_gl->left  = tmp;
    new_gl->right = curr;
    curr->left    = new_gl;
}

// Detach curr. Head / tail / middle handled cleanly; both sides
// zeroed so a subsequent insert works.
void remove_glthread(GlThread* curr){
    if(!curr->left){
        if(curr->right){
            curr->right->left = 0;
            curr->right       = 0;
            return;
        }
        return;
    }
    if(!curr->right){
        curr->left->right = 0;
        curr->left        = 0;
        return;
    }
    curr->left->right = curr->right;
    curr->right->left = curr->left;
    curr->left        = 0;
    curr->right       = 0;
}

void glthread_add_last(GlThread* base, GlThread* new_gl){
    GlThread* curr = base;
    while(curr->right){
        curr = curr->right;
    }
    glthread_add_next(curr, new_gl);
}

void delete_glthread_list(GlThread* base){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(base, cur){
        remove_glthread(cur);
    } ITERATE_GLTHREAD_END(base, cur);
}

unsigned int get_glthread_list_count(GlThread* base){
    unsigned int count = 0;
    GlThread*    cur   = 0;
    ITERATE_GLTHREAD_BEGIN(base, cur){
        count++;
    } ITERATE_GLTHREAD_END(base, cur);
    return count;
}

// Sorted insert keyed by comp_fn(new_owner, existing_owner).
// Returns -1 to insert before, 1 to keep searching, 0 to refuse.
void glthread_priority_insert(GlThread* base, GlThread* new_gl,
                              int (*comp_fn)(void*, void*),
                              int offset){
    init_glthread(new_gl);

    if(IS_GLTHREAD_LIST_EMPTY(base)){
        glthread_add_next(base, new_gl);
        return;
    }
    if(base->right && !base->right->right){
        GlThread* only = base->right;
        int cmp = comp_fn(GLTHREAD_GET_USER_DATA_FROM_OFFSET(new_gl, offset),
                          GLTHREAD_GET_USER_DATA_FROM_OFFSET(only,   offset));
        if(cmp == -1){
            glthread_add_before(only, new_gl);
        } else {
            glthread_add_next(only, new_gl);
        }
        return;
    }

    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(base, cur){
        int cmp = comp_fn(GLTHREAD_GET_USER_DATA_FROM_OFFSET(new_gl, offset),
                          GLTHREAD_GET_USER_DATA_FROM_OFFSET(cur,    offset));
        if(cmp == 0){
            return;
        }
        if(cmp == -1){
            glthread_add_before(cur, new_gl);
            return;
        }
    } ITERATE_GLTHREAD_END(base, cur);

    glthread_add_last(base, new_gl);
}
