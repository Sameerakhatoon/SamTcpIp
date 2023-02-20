#ifndef SAMTCPIP_GLTHREAD_H
#define SAMTCPIP_GLTHREAD_H

// Glue thread: a generic doubly-linked-list anchor embedded inside
// any struct. Lets one struct sit on multiple unrelated lists without
// pre-deciding which list owns it. The rest of the stack uses this
// for node lists, ARP tables, mac tables.

typedef struct GlThread GlThread;

struct GlThread {
    GlThread* left;
    GlThread* right;
};

void         init_glthread(GlThread* gl);
void         glthread_add_next(GlThread* curr, GlThread* new_gl);
void         glthread_add_before(GlThread* curr, GlThread* new_gl);
void         glthread_add_last(GlThread* base, GlThread* new_gl);
void         remove_glthread(GlThread* curr);
void         delete_glthread_list(GlThread* base);
unsigned int get_glthread_list_count(GlThread* base);
void         glthread_priority_insert(GlThread* base, GlThread* new_gl,
                                      int (*comp_fn)(void*, void*),
                                      int offset);

#define IS_GLTHREAD_LIST_EMPTY(gl_ptr) \
    ((gl_ptr)->right == 0 && (gl_ptr)->left == 0)

// Recover the owning struct pointer from a GlThread* embedded inside
// it. The GlThread can sit at any byte offset within the owner; this
// subtracts that offset from the GlThread* to get back to the owner.
#define GLTHREAD_TO_STRUCT(fn_name, structure_name, field_name)                                  \
    static inline structure_name* fn_name(GlThread* gl_ptr){                                     \
        return (structure_name*)((char*)(gl_ptr) - (char*)&(((structure_name*)0)->field_name));  \
    }

#define BASE(gl_ptr) ((gl_ptr)->right)

// Delete-safe iteration: caches `right` into a scratch var so a
// `remove_glthread(cur)` inside the body does not wreck the walk.
#define ITERATE_GLTHREAD_BEGIN(gl_start, gl_cur)             \
    {                                                        \
        GlThread* _gl_next = 0;                              \
        gl_cur = BASE(gl_start);                             \
        for(; gl_cur != 0; gl_cur = _gl_next){               \
            _gl_next = (gl_cur)->right;

#define ITERATE_GLTHREAD_END(gl_start, gl_cur) \
    }                                          \
    }

#define GLTHREAD_GET_USER_DATA_FROM_OFFSET(gl_ptr, offset) \
    (void*)((char*)(gl_ptr) - offset)

#endif
