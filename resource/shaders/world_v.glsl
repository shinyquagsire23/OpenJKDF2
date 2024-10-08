in vec3 coord3d;
in vec4 v_color;
in float v_light;
in vec4 v_uv;
in vec3 v_normal;

in vec3 coordVS;

uniform mat4 mvp;
out vec4 f_color;
out float f_light;
out vec4 f_uv;
out vec3 f_coord;
out vec3 f_normal;
out float f_depth;

uniform mat4 modelMatrix;
uniform int uv_mode;
uniform vec2 iResolution;

uniform vec2 texsize;
uniform int texgen;
uniform vec4 texgen_params;
uniform vec2 uv_offset;

noperspective out vec2 f_uv_affine;

uniform int  lightMode;

uniform vec3 ambientColor;
uniform vec4 ambientSH[3];
uniform vec3 ambientDominantDir;
uniform vec3 ambientSG[8];
uniform vec4 ambientSGBasis[8];

// https://therealmjp.github.io/posts/sg-series-part-1-a-brief-and-incomplete-history-of-baked-lighting-representations/
// SphericalGaussian(dir) := Amplitude * exp(Sharpness * (dot(Axis, dir) - 1.0f))
struct SG
{
    vec3 Amplitude;
    vec3 Axis;
    float Sharpness;
};

vec3 SGInnerProduct(SG x, SG y)
{
    float umLength = length(x.Sharpness * x.Axis + y.Sharpness * y.Axis);
    vec3 expo = exp(umLength - x.Sharpness - y.Sharpness) * x.Amplitude * y.Amplitude;
    float other = 1.0 - exp(-2.0 * umLength);
    return (2.0 * 3.141592 * expo * other) / umLength;
}

SG CosineLobeSG(vec3 direction)
{
    SG cosineLobe;
    cosineLobe.Axis = direction;
    cosineLobe.Sharpness = 2.133;
    cosineLobe.Amplitude = vec3(1.17);

    return cosineLobe;
}

vec3 SGIrradianceInnerProduct(SG lightingLobe, vec3 normal)
{
    SG cosineLobe = CosineLobeSG(normal);
    return max(SGInnerProduct(lightingLobe, cosineLobe), 0.0);
}

vec3 SGIrradiancePunctual(SG lightingLobe, vec3 normal)
{
    float cosineTerm = clamp(dot(lightingLobe.Axis, normal), 0.0, 1.0);
    return cosineTerm * 2.0 * 3.141592 * (lightingLobe.Amplitude) / lightingLobe.Sharpness;
}


vec3 ApproximateSGIntegral(in SG sg)
{
    return 2 * 3.141592 * (sg.Amplitude / sg.Sharpness);
}

vec3 SGIrradianceFitted(in SG lightingLobe, in vec3 normal)
{
    float muDotN = dot(lightingLobe.Axis, normal);
    float lambda = lightingLobe.Sharpness;

    const float c0 = 0.36f;
    const float c1 = 1.0f / (4.0f * c0);

    float eml  = exp(-lambda);
    float em2l = eml * eml;
    float rl   = 1.0/(lambda);

    float scale = 1.0f + 2.0f * em2l - rl;
    float bias  = (eml - em2l) * rl - em2l;

    float x  = sqrt(1.0f - scale);
    float x0 = c0 * muDotN;
    float x1 = c1 * x;

    float n = x0 + x1;

    float y = (abs(x0) <= x1) ? n * n / x : clamp(muDotN, 0.0, 1.0);

    float normalizedIrradiance = scale * y + bias;

    return normalizedIrradiance * ApproximateSGIntegral(lightingLobe);
}

vec3 CalculateAmbientDiffuse(vec3 normal)
{
	vec3 ambientDiffuse = vec3(0.0);
	for(int sg = 0; sg < 8; ++sg)
	{
		SG lightSG;
		lightSG.Amplitude = ambientSG[sg].xyz;
		lightSG.Axis = ambientSGBasis[sg].xyz;
		lightSG.Sharpness = ambientSGBasis[sg].w;
	
		vec3 diffuse = SGIrradiancePunctual(lightSG, normal);
		ambientDiffuse.xyz += diffuse;
	}
	return ambientDiffuse;
}

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

vec2 do_ceiling_uv(vec4 view_pos, vec3 world_pos, inout vec4 clip_pos)
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
	
	vec2 uv = sky_pos.xy * 16.0;

	vec4 proj_sky = mvp * modelMatrix * vec4(sky_pos.xyz, 1.0);

	clip_pos.z = (proj_sky.z / proj_sky.w) * clip_pos.w;
	//clip_pos.z = clip_pos.w - 0.25/64.0;
	
	return (uv + uv_offset.xy) / texsize.xy;
}

vec2 do_horizon_uv(inout vec4 clip_pos)
{
	vec2 projXY = vec2(0.5, 0.5) * clip_pos.xy;
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
    vec4 pos = mvp * viewPos;
	f_normal = normalize(mat3(modelMatrix) * v_normal.xyz);

    gl_Position = pos;
    f_color = clamp(v_color.bgra, vec4(0.0), vec4(1.0));

    f_uv = v_uv;
	f_uv.xy += uv_offset.xy;
	f_uv_affine = v_uv.xy;

	if(texgen == 1) // 1 = RD_TEXGEN_HORIZON
		f_uv.xy = f_uv_affine = do_horizon_uv(gl_Position);
	else if(texgen == 2) // 2 = RD_TEXGEN_CEILING
		f_uv.xy = f_uv_affine = do_ceiling_uv(viewPos, coord3d.xyz, gl_Position);

	f_coord = viewPos.xyz;

    f_light = v_light;
 	f_depth = pos.w / 128.0;

#ifdef UNLIT
	if(lightMode == 0) // full lit
		f_color.xyz = vec3(1.0);
	else if(lightMode == 1) // not lit
		f_color.xyz = vec3(0.0);
#else
	// do ambient diffuse in vertex shader
	if (lightMode >= 2)
		f_color.xyz = max(f_color.xyz, ambientColor.xyz);
	
	if(lightMode >= 3)
		f_color.xyz += CalculateAmbientDiffuse(f_normal);
#endif
}
