in vec3 coord3d;
in vec4 v_color;
in float v_light;
in vec2 v_uv;

in vec3 coordVS;

uniform mat4 mvp;
out vec4 f_color;
out float f_light;
out vec2 f_uv;
out vec3 f_coord;

#ifdef GPU_LIGHTING
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
#endif

void main(void)
{
#ifndef RENDER_DROID2
    vec4 pos = mvp * vec4(coord3d, 1.0);
    pos.w = 1.0/(1.0-coord3d.z); // fixme: this doesn't match the projection matrix output AT ALL
    pos.xyz *= pos.w;
#else
    vec4 pos = mvp * vec4(coord3d, 1.0);
#endif
    gl_Position = pos;
    f_color = v_color.bgra;
    f_uv = v_uv;
#ifdef VIEW_SPACE_GBUFFER
    f_coord = coordVS;
#else
    f_coord = coord3d;
#endif
    f_light = v_light;

#ifdef GPU_LIGHTING
	vec3 viewDir = normalize(-coordVS.xyz);
	float scalar = 0.4; // todo: needs to come from rdCamera_pCurCamera->attenuationMin
	int totalLights = min(numLights, 128);
	vec3 specLight = vec3(0.0);
	for(int lid = 0; lid < totalLights; ++lid)
	{
		light l = lights[lid];
		//if(l.isActive == 0u)
		//	continue;

		vec3 diff = l.position.xyz - coordVS.xyz;
		float len = length(diff);
		if ( len < l.falloffMin )
		{
			diff = normalize(diff);
			// we don't have any normals from the pipeline! this super sucks, just use distance based I guess...
			float lightMagnitude = 1.0;//dot(viewNormals, diff);
			if ( lightMagnitude > 0.0 )
			{
				float intensity = max(0.0, l.direction_intensity.w - len * scalar) * lightMagnitude;
				f_color.xyz += intensity * l.color.xyz;
			}
		}
	}
#endif
}
