#pragma once

#include "vk_render.h"
#include "vk_geometry.h"

typedef struct {
	vk_render_model_t model;
	r_geometry_range_t geometry_range;
	vk_render_geometry_t *geometries;
	int geometries_count;
	int vertex_count, index_count;
} r_studio_render_submodel_t;

typedef struct {
	const mstudiomodel_t *submodel_key;

	/* int indices_offset; */
	/* int vertices_offset; */
	/* int geometries_offset; */
	/* int vertices_count; */
	/* int indices_count; */
	/* int geometries_count; */
	qboolean is_dynamic;

	// TODO int verts_count; for prev_verts
} r_studio_submodel_info_t;

typedef struct {
	/* int total_vertices; */
	/* int total_indices; */
	/* int total_geometries; */

	int submodels_count;
	r_studio_submodel_info_t *submodels;
} r_studio_model_info_t;

/* deprecate
typedef struct {
	const mstudiomodel_t *key_submodel;

	// Non-NULL for animated instances
	const cl_entity_t *key_entity;

	r_studio_render_submodel_t render;
} r_studio_model_cache_entry_t;

typedef struct {
	const studiohdr_t *key_model;

	// Model contains no animations and can be used directly
	qboolean is_static;

	// Pre-built submodels for static, NULL if not static
	r_studio_render_submodel_t *render_submodels;
} r_studio_cached_model_t;

const r_studio_model_cache_entry_t *findSubModelInCacheForEntity(const mstudiomodel_t *submodel, const cl_entity_t *ent);
r_studio_model_cache_entry_t *studioSubModelCacheAlloc(void);
*/

void VK_StudioModelInit(void);

// Entity model cache/pool
typedef struct {
	const studiohdr_t *studio_header;
	const r_studio_model_info_t *model_info;

	// ??? probably unnecessary matrix3x4 transform;
	matrix3x4 prev_transform;
	// TODO vec3_t *prev_verts;

	// FIXME this is bodyparts, not submodels. Body parts can theoretically switch submodels used at runtime.
	int num_submodels;
	r_studio_render_submodel_t *submodels;
} r_studio_entity_model_t;

//r_studio_entity_model_t *studioEntityModelGet(const cl_entity_t *ent);

// TOOD manual cleanup function? free unused?

//void studioEntityModelClear(void);

void studioRenderSubmodelDestroy( r_studio_render_submodel_t *submodel );

r_studio_model_info_t *getStudioModelInfo(model_t *model);
