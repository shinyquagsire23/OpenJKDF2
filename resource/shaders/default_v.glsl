in vec3 coord3d;
in vec4 v_color;
in float v_light;
in vec2 v_uv;
in vec3 v_normal;

in vec3 coordVS;

uniform mat4 mvp;
out vec4 f_color;
out float f_light;
out vec2 f_uv;
out vec3 f_coord;
out vec3 f_normal;
out float f_depth;

#ifdef RENDER_DROID2
uniform mat4 modelMatrix;
uniform int uv_mode;
uniform vec2 iResolution;

uniform vec4 uv_mode_params0;
uniform vec4 uv_mode_params1;
uniform vec2 uv_offset;

uniform vec3 ambientColor;
uniform vec4 ambientSH[3];
uniform vec3 ambientDominantDir;

noperspective out vec2 f_uv_affine;

struct light
{
	vec4  position;
	vec4  direction_intensity;
	vec4  color;
	int   type;
	uint  isActive;
	float falloffMin;
	float falloffMax;
	float angleX;
	float cosAngleX;
	float angleY;
	float cosAngleY;
	float lux;
	float padding0;
	float padding1;
};

uniform int numLights;
uniform lightBlock
{
	light lights[128];
};

vec2 get_horizon_uv(inout vec4 clip_pos)
{
	float v10 = (clip_pos.x / clip_pos.w * iResolution.x * 0.5) * uv_mode_params0.x;
	float v12 = (-clip_pos.y / clip_pos.w * iResolution.y * 0.5) * uv_mode_params0.x;

	vec2 uv;
	uv.x = v10 * uv_mode_params1.x - v12 * uv_mode_params1.y + (uv_mode_params0.y);
	uv.y = v12 * uv_mode_params1.x + v10 * uv_mode_params1.y + (uv_mode_params0.z);
	
	clip_pos.z = clip_pos.w - 0.25/64.0;
	
	return (uv + uv_offset) / 256.0; // todo: from mat
}
#endif

void main(void)
{
#ifndef RENDER_DROID2
    vec4 pos = mvp * vec4(coord3d, 1.0);
    pos.w = 1.0/(1.0-coord3d.z); // fixme: this doesn't match the projection matrix output AT ALL
    pos.xyz *= pos.w; // pretty sure the problem is z here
#else
	vec4 worldPos = modelMatrix * vec4(coord3d, 1.0);
    vec4 pos = mvp * worldPos;
	f_normal = mat3(modelMatrix) * v_normal;
#endif
 	f_depth = pos.w / 128.0;
    gl_Position = pos;
    f_color = v_color.bgra;
    f_uv = v_uv;
#ifdef RENDER_DROID2
	f_uv_affine = v_uv;
	if(uv_mode == 6) // 6 = RD_TEXTUREMODE_HORIZON
		f_uv_affine = get_horizon_uv(pos);
#endif
#ifdef VIEW_SPACE_GBUFFER
    f_coord = coordVS;
#else
    f_coord = coord3d;
#endif
    f_light = v_light;

#ifdef RENDER_DROID2
	// todo: ambient mode
	//if (false)
	//{
	//	const float c = 0.282094792;
	//	const float k = 0.488602512;
	//
	//	vec4 shN;
	//	shN.x = c;
	//	shN.yzw = vec3(-k, k, -k) * f_normal.yzx;
	//
	//	vec3 amb;
	//	amb.x = dot(shN, ambientSH[0]);
	//	amb.y = dot(shN, ambientSH[1]);
	//	amb.z = dot(shN, ambientSH[2]);
	//
	//	f_color.xyz += max(vec3(0.0), amb) / 3.141592;
	//}


	float scalar = 0.4; // todo: needs to come from rdCamera_pCurCamera->attenuationMin
	int totalLights = min(numLights, 128);
	for(int lid = 0; lid < totalLights; ++lid)
	{
		light l = lights[lid];
		//if(l.isActive == 0u)
		//	continue;

		vec3 diff = l.position.xyz - worldPos.xyz;
		float len = length(diff);
		if ( len < l.falloffMin )
		{
			diff = normalize(diff);	
			float lightMagnitude = dot(f_normal, diff);
			if ( lightMagnitude > 0.0 )
			{
				float intensity = max(0.0, l.direction_intensity.w - len * scalar) * lightMagnitude;
				f_color.xyz += intensity * l.color.xyz;
			}
		}
	}
#endif
}
