in vec3 coord3d;
in vec4 v_color;
in float v_light;
in vec4 v_uv;
in vec3 v_normal;

in vec3 coordVS;

uniform mat4 projMatrix;
out vec4 f_color;
out float f_light;
out vec4 f_uv;
out vec3 f_coord;
out vec3 f_normal;
out float f_depth;

uniform mat4 modelMatrix;
uniform int uv_mode;

uniform vec2 texsize;
uniform int texgen;
uniform vec4 texgen_params;
uniform vec2 uv_offset;

uniform sharedBlock
{
	vec4  ambientSGBasis[8];

	vec4  colorEffects_tint;
	vec4  colorEffects_filter;
	vec4  colorEffects_add;
	
	vec4  mipDistances;

	float colorEffects_fade;
	float light_mult;
	uint  pad0;
	uint  pad1;

	vec2  clusterTileSizes;
	vec2  clusterScaleBias;

	vec2  iResolution;
	uint  firstLight;
	uint  numLights;

	uint  firstOccluder;
	uint  numOccluders;
	uint  firstDecal;
	uint  numDecals;
};

noperspective out vec2 f_uv_affine;

bool ceiling_intersect(vec3 pos, vec3 dir, vec3 normal, vec3 center, inout float t)
{
	float denom = dot(dir, normal);
	if (abs(denom) > 1e-6)
	{
		t = dot(center - pos, normal) / denom;
		if (t >= 0.0 && t < 1000.0)
		{
			return true;
		}
	}
	return false;
}

vec2 do_ceiling_uv(inout vec4 viewPos, vec3 world_pos, inout vec4 clip_pos)
{
	mat4 invMat = inverse(modelMatrix); // fixme: expensive + only works when model component is identity
	vec3 cam_pos   = (invMat * vec4(0, 0, 0, 1)).xyz;

	vec3 ray_dir = normalize(world_pos.xyz - cam_pos.xyz);
	vec3 view_ceiling = texgen_params.xyz;
	vec3 view_norm = vec3(0,0,-1);

	float tmp = 0.0;
	if (!ceiling_intersect(cam_pos, ray_dir, view_norm, view_ceiling.xyz, tmp))
		tmp = 1000.0;

    vec3 sky_pos = tmp * ray_dir + cam_pos;
	
	viewPos.y = sky_pos.y;

	vec2 uv = sky_pos.xy * 16.0;

	vec4 proj_sky = projMatrix * modelMatrix * vec4(sky_pos.xyz, 1.0);

	clip_pos.z = (proj_sky.z / proj_sky.w) * clip_pos.w;
	//clip_pos.z = clip_pos.w - 0.25/64.0;
	
	return (uv + uv_offset.xy) / texsize.xy;
}

vec2 do_horizon_uv(inout vec4 viewPos, inout vec4 clip_pos)
{
	vec2 projXY = vec2(0.5,-0.5) * clip_pos.xy;
	projXY = projXY.xy * iResolution.xy * (texgen_params.x / clip_pos.w);

	vec2 uv;
	uv.x = projXY.x * texgen_params.y + (projXY.y * -texgen_params.z);
	uv.y = projXY.y * texgen_params.y + (projXY.x *  texgen_params.z);
	
	clip_pos.z = clip_pos.w - 0.25/64.0;
	
	return (uv + uv_offset.xy) / texsize.xy;
}


void main(void)
{
	vec4 viewPos = modelMatrix * vec4(coord3d, 1.0);
    vec4 pos = projMatrix * viewPos;
	f_normal = normalize(mat3(modelMatrix) * v_normal.xyz);

    gl_Position = pos;
    f_color = v_color.bgra;

    f_uv = v_uv;
	f_uv.xy += uv_offset.xy;
	f_uv_affine = v_uv.xy;

	if(texgen == 1) // 1 = RD_TEXGEN_HORIZON
		f_uv.xy = f_uv_affine = do_horizon_uv(viewPos, gl_Position);
	else if(texgen == 2) // 2 = RD_TEXGEN_CEILING
		f_uv.xy = f_uv_affine = do_ceiling_uv(viewPos, coord3d.xyz, gl_Position);

	f_coord = viewPos.xyz;

    f_light = v_light;
 	f_depth = pos.w / 128.0;
}
