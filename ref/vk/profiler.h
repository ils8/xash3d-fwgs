#pragma once

#include <stdint.h>
#include <assert.h>
#include <string.h>

// Note: this module initializes itself on the first scope initialization.
// I.e. it is invalid to call any of the functions before the first of aprof_scope_init/APROF_SCOPE_INIT/APROF_SCOPE_DECLARE_BEGIN is called.
// TODO: explicit initialization function
//
// dirt: mmap scope, events, frame fence to ram, then, when >50mb to disk


#define APROF_SCOPE_DECLARE(scope) \
	static aprof_scope_id_t _aprof_scope_id_##scope = -1

// scope_name is expected to be static and alive for the entire duration of the program
#define APROF_SCOPE_INIT_EX(scope, scope_name, flags) \
	_aprof_scope_id_##scope = aprof_scope_init(scope_name, flags, __FILE__, __LINE__)

#define APROF_SCOPE_INIT(scope, scope_name) APROF_SCOPE_INIT_EX(scope, scope_name, 0)

#define APROF_SCOPE_BEGIN(scope) \
	aprof_scope_event(_aprof_scope_id_##scope, 1)

#define APROF_SCOPE_DECLARE_BEGIN_EX(scope, scope_name, flags) \
	static aprof_scope_id_t _aprof_scope_id_##scope = -1; \
	if (_aprof_scope_id_##scope == -1) { \
		_aprof_scope_id_##scope = aprof_scope_init(scope_name, flags, __FILE__, __LINE__); \
	} \
	aprof_scope_event(_aprof_scope_id_##scope, 1)

#define APROF_SCOPE_DECLARE_BEGIN(scope, scope_name) APROF_SCOPE_DECLARE_BEGIN_EX(scope, scope_name, 0)

#define APROF_TOKENPASTE(x, y) x ## y
#define APROF_TOKENPASTE2(x, y) APROF_TOKENPASTE(x, y)

#define APROF_SCOPE_BEGIN_EARLY(scope) \
	const int APROF_TOKENPASTE2(_aprof_dummy, __LINE__) = (aprof_scope_event(_aprof_scope_id_##scope, 1), 0)

#define APROF_SCOPE_END(scope) \
	aprof_scope_event(_aprof_scope_id_##scope, 0)


typedef int aprof_scope_id_t;

// scope_name should be static const, and not on stack
aprof_scope_id_t aprof_scope_init(const char *scope_name, uint32_t flags, const char *source_file, int source_line);
void aprof_scope_event(aprof_scope_id_t, int begin);
// Returns event index for previous frame
uint32_t aprof_scope_frame( void );
uint64_t aprof_time_now_ns( void );

#if defined(_WIN32)
uint64_t aprof_time_platform_to_ns( uint64_t );
#else
#define aprof_time_platform_to_ns(time) ((time) - g_aprof.time_begin_ns)
#endif

enum {
	// This scope covers waiting for external event.
	// Its entire subtree shouldn't count towards CPU usage by external analyzers.
	APROF_SCOPE_FLAG_WAIT = (1<<0),

	// This scope itself doesn't really mean CPU work, and used only as a frame structure decoration.
	// External tools shouldn't count it itself as CPU time used, but its children should be.
	APROF_SCOPE_FLAG_DECOR = (1<<1),
};

typedef struct {
	const char *name;
	uint32_t flags;
	const char *source_file;
	int source_line;
} /* dirt: need this thing */ aprof_scope_t;

#define APROF_MAX_SCOPES 256

#define APROF_EVENT_TYPE_MASK 0x0full
#define APROF_EVENT_TYPE_SHIFT 0
#define APROF_EVENT_TYPE(event) (((event)&APROF_EVENT_TYPE_MASK) >> APROF_EVENT_TYPE_SHIFT)

#define APROF_EVENT_SCOPE_ID_MASK 0xff00ull
#define APROF_EVENT_SCOPE_ID_SHIFT 8
#define APROF_EVENT_SCOPE_ID(event) (((event)&APROF_EVENT_SCOPE_ID_MASK) >> APROF_EVENT_SCOPE_ID_SHIFT)

#define APROF_EVENT_TIMESTAMP_SHIFT 16
#define APROF_EVENT_TIMESTAMP(event) ((event) >> APROF_EVENT_TIMESTAMP_SHIFT)


#define APROF_EVENT_MAKE(type, scope_id, timestamp) \
	(((type) << APROF_EVENT_TYPE_SHIFT) & APROF_EVENT_TYPE_MASK) | \
	(((scope_id) << APROF_EVENT_SCOPE_ID_SHIFT) & APROF_EVENT_SCOPE_ID_MASK) | \
	((timestamp) << APROF_EVENT_TIMESTAMP_SHIFT)

enum {
	// dirt: need frame fence
	APROF_EVENT_FRAME_BOUNDARY = 0,

	APROF_EVENT_SCOPE_BEGIN = 1,
	APROF_EVENT_SCOPE_END = 2,
};

// MUST be power of 2
#define APROF_EVENT_BUFFER_SIZE (1<<20) // 1000 0000 0000 0000 0000  0x80000 1*2^20 == 1024*1024
#define APROF_EVENT_BUFFER_SIZE_MASK (APROF_EVENT_BUFFER_SIZE - 1)

typedef uint64_t aprof_event_t;

typedef struct {
	uint64_t time_begin_ns;

	aprof_scope_t scopes[APROF_MAX_SCOPES];
	int num_scopes;

	aprof_event_t events[APROF_EVENT_BUFFER_SIZE];
	uint32_t events_write;
	uint32_t events_last_frame;

	int current_frame_wraparounds;

	// TODO event log for chrome://trace (or similar) export and analysis
} /* dirt: need this */aprof_state_t;

extern aprof_state_t g_aprof;

#if defined(APROF_IMPLEMENT)

#ifdef __linux__
#include <time.h>
uint64_t aprof_time_now_ns( void ) {
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return tp.tv_nsec + tp.tv_sec * 1000000000ull;
}
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN
#include <windows.h>
static LARGE_INTEGER _aprof_frequency;
uint64_t aprof_time_now_ns( void ) {
	LARGE_INTEGER pc;
	QueryPerformanceCounter(&pc);
	return pc.QuadPart * 1000000000ull / _aprof_frequency.QuadPart;
}

uint64_t aprof_time_platform_to_ns( uint64_t platform_time ) {
	return platform_time * 1000000000ull / _aprof_frequency.QuadPart - g_aprof.time_begin_ns;
}
#else
#error aprof is not implemented for this os
#endif

aprof_state_t g_aprof = {0};



// state = events + scopes, where is frame stuff?
int dump_to_ram(aprof_state_t *state){
	for(int i=state->num_scopes; i; --i){
		// addr starting address of mapping
		// len length of the mapping >0
		// if addr == 0, page-aligned address by kernel
		// else addr+= len to boundary
		// mmap returns address
		// offset - into the fd
		// offset % sysconf(_SC_PAGE_SIZE) = 0
		// can close fd right after return mmap
		// 
		
	//	void *mmap(
				/* new mapping, if 0 os assign */	//void addr[.length],
				/* len of mapping >0! */					//size_t len, 
				/* mem condoms */									//int prot,
				/* rwen */												//int flags, 
				/* object to map from */					//int fd,
				/* offset into above object */		//off_t offset
	//	);
		
		/*
		 * delete mappings for addr len
		 * refs SIGSEGV!!
		 * also called at process deth
		 * fd doesnt close lol
		 * addr % page_size = 0!
		 * ok to call on random address
		 * succ return 0
		 * err return -1
		 */
	/*
	int munmap(
				 		void addr[.length],
						size_t length
	);
	*/	
#include <stdio.h>

    FILE *dt_file = fopen("states", "a");
    if(dt_file == NULL)
      printf("error: couldn't open states\n");
    else
      fprintf(dt_file, "%s\n", state->scopes[i].name);
    fclose(dt_file);
    // end of dirt
	}

	return 0;
}

int dump_to_disk(void){

	return 0;
}



aprof_scope_id_t aprof_scope_init(const char *scope_name, uint32_t flags, const char *source_file, int source_line) {
#if defined(_WIN32)
	if (_aprof_frequency.QuadPart == 0)
		QueryPerformanceFrequency(&_aprof_frequency);
#endif

	if (!g_aprof.time_begin_ns)
		g_aprof.time_begin_ns = aprof_time_now_ns();

	if (g_aprof.num_scopes /* dirt: concurrency LOL */ >= APROF_MAX_SCOPES)
		return -1;

	g_aprof.scopes[g_aprof.num_scopes].name = scope_name;
	g_aprof.scopes[g_aprof.num_scopes].flags = flags;
	g_aprof.scopes[g_aprof.num_scopes].source_file = source_file;
	g_aprof.scopes[g_aprof.num_scopes].source_line = source_line;

	++g_aprof.num_scopes;
	dump_to_ram(&g_aprof);

	return g_aprof.num_scopes; // dirt: atomic?
}

void aprof_scope_event(aprof_scope_id_t scope_id, int /* bool */ begin /* /end */) {
	const uint64_t now = aprof_time_now_ns() - g_aprof.time_begin_ns;
	if (scope_id < 0 || scope_id >= g_aprof.num_scopes)
		return;

	g_aprof.events[g_aprof.events_write] = APROF_EVENT_MAKE(begin?APROF_EVENT_SCOPE_BEGIN:APROF_EVENT_SCOPE_END, scope_id, now);
	g_aprof.events_write = (g_aprof.events_write + 1) & APROF_EVENT_BUFFER_SIZE_MASK;

	// dirt: if current events == prev, we wrapped; wut but what if we didnt do anything to current???
	if (g_aprof.events_write == g_aprof.events_last_frame)
		++g_aprof.current_frame_wraparounds; // dirt: what this? ah, remember prev frame scope
}

uint32_t aprof_scope_frame( void ) {
	const uint64_t now = aprof_time_now_ns() - g_aprof.time_begin_ns;
	const uint32_t previous_frame = g_aprof.events_last_frame;

	// dirt: advance events by one
	g_aprof.events_last_frame = g_aprof.events_write;
	g_aprof.events[g_aprof.events_write] = APROF_EVENT_MAKE(APROF_EVENT_FRAME_BOUNDARY, 0, now);
	g_aprof.events_write = (g_aprof.events_write + 1) & APROF_EVENT_BUFFER_SIZE_MASK;

	g_aprof.current_frame_wraparounds = 0;

	return previous_frame;
}

#endif
