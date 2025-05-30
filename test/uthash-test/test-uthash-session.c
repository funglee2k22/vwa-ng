
#include "session.h"
#include "uthash.h"
#include <stdio.h>
#include <stdlib.h> 


session_t *q2t = NULL;
session_t *t2q = NULL;

void add_to_hash_t2q(session_t **hh, session_t *s) 
{ 
     session_t *t = NULL; 
     int fd = s->fd; 

     HASH_FIND(hh_t2q, *hh, &fd, sizeof(fd), t);

     if (t == NULL) {
         HASH_ADD(hh_t2q, *hh, fd, sizeof(fd), s); 
     } else { 
	 //HASH_REPLACE(hh_t2q, *hh, fd, sizeof(fd), s, t);  
     }
     return; 
}

session_t *find_session_t2q(session_t **hh, int fd) 
{ 
    session_t *r = NULL;
    
    HASH_FIND(hh_t2q, *hh, &fd, sizeof(fd), r);
    
    return r;
}

void add_to_hash_q2t(session_t **hh, session_t *s) 
{ 
     session_t *t = NULL; 
     long int stream_id = s->stream_id; 

     HASH_FIND(hh_q2t, *hh, &stream_id, sizeof(stream_id), t);
     if (t == NULL) {
         HASH_ADD(hh_q2t, *hh, stream_id, sizeof(stream_id), s); 
     } else { 
	 HASH_REPLACE(hh_q2t, *hh, stream_id, sizeof(stream_id), s, t);  
     }
     return; 
}

session_t *find_session_q2t(session_t **hh, long int stream_id) 
{ 
    session_t *r = NULL;
    
    HASH_FIND(hh_q2t, *hh, &stream_id, sizeof(stream_id), r);
    
    return r;
}


void delete_session(session_t **t2q, session_t **q2t, session_t *s) 
{
    if (!s) 
	return;

    if (t2q) 
        HASH_DELETE(hh_t2q, *t2q, s);
 
    if (q2t)  
        HASH_DELETE(hh_q2t, *q2t, s); 

    return;
}


int main()
{ 
    int i = 0;
    for (i = 0; i < 10; ++i) { 
	printf("i = %d.\n", i);
        session_t *ns = malloc(sizeof(session_t)); 
	ns->stream_id = i * 10 + 1; 
	ns->fd = i; 
	add_to_hash_t2q(&t2q, ns);
	add_to_hash_q2t(&q2t, ns);
    }

    printf("t2q elements: %d\n", HASH_CNT(hh_t2q, t2q));
    printf("q2t elements: %d\n", HASH_CNT(hh_q2t, q2t));


    session_t *expect = NULL, *actual = NULL; 
    actual = find_session_t2q(&t2q, 1);
    assert(actual->fd == 1);

    printf("line: %d passed.\n", __LINE__);

    actual = find_session_t2q(&t2q, 3000);
    assert(actual == NULL);

    printf("line: %d passed.\n", __LINE__);

    actual = find_session_q2t(&q2t, 11);
    assert(actual->stream_id == 11);

    printf("line: %d passed.\n", __LINE__);

    actual = find_session_q2t(&q2t, 3000);
    assert(actual == NULL);
   
    printf("line: %d passed.\n", __LINE__);    

    actual = find_session_t2q(&t2q, 3);
    delete_session(&t2q, NULL, actual); 
    expect = actual;
    actual = find_session_t2q(&t2q, 3);
    assert(actual == NULL); 
    printf("line: %d passed.\n", __LINE__);    

    actual = find_session_q2t(&q2t, expect->stream_id); 
    assert(actual == expect);
    printf("line: %d passed.\n", __LINE__);    

    delete_session(NULL, &q2t, expect);
    actual = find_session_q2t(&q2t, expect->stream_id);
    assert(actual == NULL);
    printf("line: %d passed.\n", __LINE__);    
    
    actual = find_session_t2q(&t2q, expect->fd);
    assert(actual == NULL);

    printf("line: %d passed.\n", __LINE__);    
    free(expect);


    return 0;


}

