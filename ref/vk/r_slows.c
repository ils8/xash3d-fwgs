#include "r_slows.h"
#include "vk_light.h" // For stats
#include "shaders/ray_interop.h" // stats: struct LightCluster
#include "vk_overlay.h"
#include "vk_framectl.h"

#include "profiler.h"

#include "crclib.h" // CRC32 for stable random colors
#include "xash3d_mathlib.h" // Q_min

#define MAX_FRAMES_HISTORY 256
#define TARGET_FRAME_TIME (1000.f / 60.f)

static struct {
	float frame_times[MAX_FRAMES_HISTORY];
	uint32_t frame_num;
} g_slows;

static float linearstep(float min, float max, float v) {
	if (v <= min) return 0;
	if (v >= max) return 1;
	return (v - min) / (max - min);
}

#define P(fmt, ...) gEngine.Con_Reportf(fmt, ##__VA_ARGS__)

static uint32_t getHash(const char *s) {
	dword crc;
	CRC32_Init(&crc);
	CRC32_ProcessBuffer(&crc, s, Q_strlen(s));
	return CRC32_Final(crc);
}

static void drawProfilerScopes(uint64_t frame_begin_time, float time_scale_ms, uint32_t begin, uint32_t end, int y) {
#define MAX_STACK_DEPTH 16
	const int height = 20;

	struct {
		int scope_id;
		uint64_t begin_ns;
	} stack[MAX_STACK_DEPTH];
	int depth = 0;
	int max_depth = 0;

	for (; begin != end; begin = (begin + 1) % APROF_EVENT_BUFFER_SIZE) {
		const aprof_event_t event = g_aprof.events[begin];
		const int event_type = APROF_EVENT_TYPE(event);
		const uint64_t timestamp_ns = APROF_EVENT_TIMESTAMP(event);
		const int scope_id = APROF_EVENT_SCOPE_ID(event);
		switch (event_type) {
			case APROF_EVENT_SCOPE_BEGIN: {
					if (depth < MAX_STACK_DEPTH) {
						stack[depth].begin_ns = timestamp_ns;
						stack[depth].scope_id = scope_id;
					}
					++depth;
					if (max_depth < depth)
						max_depth = depth;
					break;
				}

			case APROF_EVENT_SCOPE_END: {
					ASSERT(depth > 0);
					--depth;

					ASSERT(stack[depth].scope_id == scope_id);

					const int width = (timestamp_ns - stack[depth].begin_ns) * 1e-6 * time_scale_ms;
					const int x = (stack[depth].begin_ns - frame_begin_time) * 1e-6 * time_scale_ms;

					const int yy = y + depth * height;
					const char *scope_name = g_aprof.scopes[scope_id].name;
					const uint32_t hash = getHash(scope_name);

					rgba_t color = {hash >> 24, (hash>>16)&0xff, hash&0xff, 127};
					rgba_t text_color = {255-color[0], 255-color[1], 255-color[2], 255};
					CL_FillRGBA(x, yy, width, height, color[0], color[1], color[2], color[3]);
					char tmp[64];
					tmp[0] = '\0';
					Q_strncpy(tmp, scope_name, Q_min(sizeof(tmp), width / 10));
					gEngine.Con_DrawString(x, yy, tmp, text_color);
					break;
				}

			default:
				break;
		}
	}

	if (max_depth > MAX_STACK_DEPTH)
		gEngine.Con_NPrintf(4, S_ERROR "Profiler stack overflow: reached %d, max available %d\n", max_depth, MAX_STACK_DEPTH);
}

// FIXME move this to r_speeds or something like that
void R_ShowExtendedProfilingData(uint32_t prev_frame_index) {
	{
		const int dirty = g_lights.stats.dirty_cells;
		gEngine.Con_NPrintf(4, "Dirty light cells: %d, size = %dKiB, ranges = %d\n", dirty, (int)(dirty * sizeof(struct LightCluster) / 1024), g_lights.stats.ranges_uploaded);
	}

	const uint32_t events = g_aprof.events_last_frame - prev_frame_index;
	const uint64_t frame_begin_time = APROF_EVENT_TIMESTAMP(g_aprof.events[prev_frame_index]);
	const unsigned long long delta_ns = APROF_EVENT_TIMESTAMP(g_aprof.events[g_aprof.events_last_frame]) - frame_begin_time;
	const float frame_time = delta_ns / 1e6;

	gEngine.Con_NPrintf(5, "aprof events this frame: %u, wraps: %d, frame time: %.03fms\n", events, g_aprof.current_frame_wraparounds, frame_time);

	g_slows.frame_times[g_slows.frame_num] = frame_time;
	g_slows.frame_num = (g_slows.frame_num + 1) % MAX_FRAMES_HISTORY;

	const float width = (float)vk_frame.width / MAX_FRAMES_HISTORY;
	const int frame_bar_y = 100;
	const float frame_bar_y_scale = 2.f; // ms to pixels

	// 60fps
	CL_FillRGBA(0, frame_bar_y + frame_bar_y_scale * TARGET_FRAME_TIME, vk_frame.width, 1, 0, 255, 0, 50);

	// 30fps
	CL_FillRGBA(0, frame_bar_y + frame_bar_y_scale * TARGET_FRAME_TIME * 2, vk_frame.width, 1, 255, 0, 0, 50);

	for (int i = 0; i < MAX_FRAMES_HISTORY; ++i) {
		const float frame_time = g_slows.frame_times[(g_slows.frame_num + i) % MAX_FRAMES_HISTORY];

		// > 60 fps => 0, 30..60 fps -> 1..0, <30fps => 1
		const float time = linearstep(TARGET_FRAME_TIME, TARGET_FRAME_TIME*2.f, frame_time);
		const int red = 255 * time;
		const int green = 255 * (1 - time);
		CL_FillRGBA(i * width, frame_bar_y, width, frame_time * frame_bar_y_scale, red, green, 0, 127);
	}

	{
		const float time_scale_ms = (double)vk_frame.width / (delta_ns / 1e6);
		const int y = frame_bar_y + frame_bar_y_scale * TARGET_FRAME_TIME * 2;
		drawProfilerScopes(frame_begin_time, time_scale_ms, prev_frame_index, g_aprof.events_last_frame, y);
	}

	/* gEngine.Con_NPrintf(5, "Perf scopes:"); */
	/* for (int i = 0; i < g_aprof.num_scopes; ++i) { */
	/* 	const aprof_scope_t *const scope = g_aprof.scopes + i; */
	/* 	gEngine.Con_NPrintf(6 + i, "%s: c%d t%.03f(%.03f)ms s%.03f(%.03f)ms", scope->name, */
	/* 		scope->frame.count, */
	/* 		scope->frame.duration / 1e6, */
	/* 		(scope->frame.duration / 1e6) / scope->frame.count, */
	/* 		(scope->frame.duration - scope->frame.duration_children) / 1e6, */
	/* 		(scope->frame.duration - scope->frame.duration_children) / 1e6 / scope->frame.count); */
	/* } */
}
