in vec3 coord3d;
in vec4 v_color;
in float v_light;
#ifdef RENDER_DROID2
in vec4 v_uv;
#else
in vec2 v_uv;
#endif
in vec3 v_normal;

in vec3 coordVS;

uniform mat4 mvp;
out vec4 f_color;
out float f_light;
#ifdef RENDER_DROID2
out vec4 f_uv;
#else
out vec2 f_uv;
#endif
out vec3 f_coord;
out vec3 f_normal;
out float f_depth;

#ifdef RENDER_DROID2
uniform mat4 modelMatrix;
uniform int uv_mode;
uniform vec2 iResolution;

uniform vec4 texgen_params;
uniform vec2 uv_offset;

uniform int lightMode;
uniform int  ambientMode;
uniform vec3 ambientColor;
uniform vec4 ambientSH[3];
uniform vec3 ambientDominantDir;

noperspective out vec2 f_uv_affine;
out vec3 f_spec;

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

vec3 do_ambient(vec3 normal)
{
	const float c = 0.282094792;
	const float k = 0.488602512;
	
	vec4 shN;
	shN.x =  c;
	shN.y = -k * normal.y;
	shN.z =  k * normal.z;
	shN.w = -k * normal.x;
				
	vec3 amb;
	amb.x = dot(shN, ambientSH[0]);
	amb.y = dot(shN, ambientSH[1]);
	amb.z = dot(shN, ambientSH[2]);

	return max(vec3(0.0), amb) / 3.141592;
}

float do_half_lambert(float ndotl)
{
	ndotl = ndotl * 0.5f + 0.5f;
	return ndotl * ndotl;
}

float do_specular(vec3 lightDir, vec3 viewDir, vec3 normal)
{
	vec3 h = normalize(lightDir + viewDir);
	float brdf = clamp(dot(h, normal), 0.0, 1.0);
	brdf *= brdf; // x2
	brdf *= brdf; // x4
	brdf *= brdf; // x8
	return brdf;
}

float do_fresnel(vec3 viewDir, vec3 normal, float f0)
{
	float fresnel = abs(1.0 - dot(normal, viewDir));
	fresnel *= fresnel;
	fresnel *= fresnel;
	return f0 + (1.0 - f0) * fresnel;
}

vec2 do_horizon_uv(inout vec4 clip_pos)
{
	float v10 = (clip_pos.x / clip_pos.w * iResolution.x * 0.5) * texgen_params.x;
	float v12 = (-clip_pos.y / clip_pos.w * iResolution.y * 0.5) * texgen_params.x;

	vec2 uv;
	uv.x = v10 * texgen_params.y - v12 * texgen_params.z;
	uv.y = v12 * texgen_params.y + v10 * texgen_params.z;
	
	clip_pos.z = clip_pos.w - 0.25/64.0;
	
	return uv / 256.0; // todo: from mat
}
#endif

void main(void)
{
#ifndef RENDER_DROID2
    vec4 pos = mvp * vec4(coord3d, 1.0);
    pos.w = 1.0/(1.0-coord3d.z); // fixme: this doesn't match the projection matrix output AT ALL
    pos.xyz *= pos.w; // pretty sure the problem is z here
#else
	vec4 viewPos = modelMatrix * vec4(coord3d, 1.0);
    vec4 pos = mvp * viewPos;
	f_normal = mat3(modelMatrix) * v_normal.xyz;
#endif
 	f_depth = pos.w / 128.0;
    gl_Position = pos;
    f_color = v_color.bgra;
    f_uv = v_uv;
#ifdef RENDER_DROID2
	f_uv_affine = v_uv.xy;
	if(uv_mode == 6) // 6 = RD_TEXTUREMODE_HORIZON
		f_uv_affine = do_horizon_uv(pos);

	f_uv.xy += uv_offset.xy;
	f_uv_affine.xy += uv_offset.xy;
#endif
#ifdef VIEW_SPACE_GBUFFER
    f_coord = coordVS;
#else
    f_coord = coord3d;
#endif
    f_light = v_light;

#ifdef RENDER_DROID2
	f_spec = vec3(0.0);

	if(lightMode == 0) // full lit
	{
		f_color.xyz = vec3(1.0);
	}
	else if(lightMode == 1) // not lit
	{
		f_color.xyz = vec3(0.0);
	}
	else if(lightMode >= 2)
	{
		vec3 shadeNormal = f_normal;
		vec3 localViewDir = normalize(-viewPos.xyz);

		float scalar = 0.4; // todo: needs to come from rdCamera_pCurCamera->attenuationMin
		int totalLights = min(numLights, 128);
		for(int lid = 0; lid < totalLights; ++lid)
		{
			light l = lights[lid];
			//if(l.isActive == 0u)
			//	continue;

			vec3 diff = l.position.xyz - viewPos.xyz;
			float len;
			if (lightMode == 2) // diffuse uses dist to plane
				len = dot(l.position.xyz - viewPos.xyz, shadeNormal.xyz);
			else
				len = length(diff);

			if ( len < l.falloffMin )
			{
				diff = normalize(diff);
				float lightMagnitude = dot(shadeNormal, diff);
				if (lightMode > 2)
					lightMagnitude = do_half_lambert(lightMagnitude);

				if ( lightMagnitude > 0.0 )
				{
					float intensity = max(0.0, l.direction_intensity.w - len * scalar) * lightMagnitude;
					f_color.xyz += intensity * l.color.xyz;

					if(lightMode == 4)
						f_spec.xyz += intensity * do_specular(diff, localViewDir, shadeNormal);
				}
			}
		}

		if (ambientMode > 0)
			f_color.xyz = max(f_color.xyz, ambientColor.xyz);

		if (ambientMode == 2)
		{
			f_color.xyz += do_ambient(shadeNormal);

			if(lightMode == 4)
			{
				float brdf = do_specular(ambientDominantDir, localViewDir, shadeNormal);
				
				// add some view based fresnel
				brdf += do_fresnel(localViewDir, shadeNormal, 0.0);

				vec3 reflDir = reflect(-ambientDominantDir, shadeNormal);
				f_spec.xyz += do_ambient(reflDir) * brdf;
			}
		}

		// todo: verify if we want to keep clamping or maybe want something else
		f_color.xyz = clamp(f_color.xyz, vec3(0.0), vec3(1.0));
	}
#endif
}
