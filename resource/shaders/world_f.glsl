#ifdef GL_ARB_texture_query_lod
float impl_textureQueryLod(sampler2D tex, vec2 uv)
{
	return textureQueryLOD(tex, uv).x;
}
#else
float impl_textureQueryLod(sampler2D tex, vec2 uv)
{
    vec2 dims = textureSize(tex, 0);
	vec2  texture_coordinate = uv * dims;
    vec2  dx_vtc        = dFdx(texture_coordinate);
    vec2  dy_vtc        = dFdy(texture_coordinate);
    float delta_max_sqr = max(dot(dx_vtc, dx_vtc), dot(dy_vtc, dy_vtc));
    float mml = 0.5 * log2(delta_max_sqr);
    return max( 0, mml );
}
#endif

// if we don't have native support for findLSB (necessary for the clustered bit scan), implement it
#ifndef GL_ARB_gpu_shader5
uint bitCount(uint n)
{
    n = ((0xaaaaaaaau & n) >>  1) + (0x55555555u & n);
    n = ((0xccccccccu & n) >>  2) + (0x33333333u & n);
    n = ((0xf0f0f0f0u & n) >>  4) + (0x0f0f0f0fu & n);
    n = ((0xff00ff00u & n) >>  8) + (0x00ff00ffu & n);
    n = ((0xffff0000u & n) >> 16) + (0x0000ffffu & n);
    return n;
}

int findLSB(uint x)
{
	return (x == 0u) ? -1 : int(bitCount(~x & (x - 1u)));
}
#endif

#define LIGHT_DIVISOR (3.0)

#define TEX_MODE_TEST 0
#define TEX_MODE_WORLDPAL 1
#define TEX_MODE_BILINEAR 2
#define TEX_MODE_16BPP 5
#define TEX_MODE_BILINEAR_16BPP 6

#define D3DBLEND_ONE             (2)
#define D3DBLEND_SRCALPHA        (5)
#define D3DBLEND_INVSRCALPHA     (6)

uniform sampler2D tex;
uniform sampler2D texEmiss;
uniform sampler2D worldPalette;
uniform sampler2D worldPaletteLights;
uniform sampler2D displacement_map;

uniform usamplerBuffer clusterBuffer;
uniform sampler2D decalAtlas;

uniform int tex_mode;
uniform vec3 emissiveFactor;
uniform vec4 albedoFactor;
uniform float displacement_factor;

#ifdef FOG
uniform int fogEnabled;
uniform vec4 fogColor;
uniform float fogStart;
uniform float fogEnd;
#endif

in vec4 f_color;
in float f_light;
in vec4 f_uv;
in vec3 f_coord;
in vec3 f_normal;
in float f_depth;

noperspective in vec2 f_uv_affine;

uniform uint renderCaps;
uniform mat4 modelMatrix;
uniform mat4 projMatrix;

uniform vec2 texsize;
uniform int  numMips;
uniform int  uv_mode;
uniform vec4 fillColor;

uniform int  lightMode;
uniform int  geoMode;
uniform int  ditherMode;

uniform vec3 ambientColor;
uniform vec4 ambientSH[3];
uniform vec3 ambientDominantDir;
uniform vec3 ambientSG[8];

// todo: define outside
#define CLUSTER_MAX_LIGHTS          256u // match RDCAMERA_MAX_LIGHTS/SITHREND_NUM_LIGHTS
#define CLUSTER_MAX_OCCLUDERS       128u
#define CLUSTER_MAX_DECALS          256
#define CLUSTER_MAX_ITEMS           (CLUSTER_MAX_LIGHTS + CLUSTER_MAX_OCCLUDERS + CLUSTER_MAX_DECALS)
#define CLUSTER_BUCKETS_PER_CLUSTER (CLUSTER_MAX_ITEMS / 32u)
#define CLUSTER_GRID_SIZE_X         16u
#define CLUSTER_GRID_SIZE_Y         8u
#define CLUSTER_GRID_SIZE_Z         24u
#define CLUSTER_GRID_SIZE_XYZ (CLUSTER_GRID_SIZE_X * CLUSTER_GRID_SIZE_Y * CLUSTER_GRID_SIZE_Z)
#define CLUSTER_GRID_TOTAL_SIZE (CLUSTER_GRID_SIZE_X * CLUSTER_GRID_SIZE_Y * CLUSTER_GRID_SIZE_Z * CLUSTER_BUCKETS_PER_CLUSTER)

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

struct light
{
	vec4  position;
	vec4  direction_intensity;
	vec4  color;
	
	int   type;
	float falloffMin;
	float falloffMax;
	float lux;
	
	float angleX;
	float cosAngleX;
	float angleY;
	float cosAngleY;
};

uniform lightBlock
{
	light lights[CLUSTER_MAX_LIGHTS];
};

struct occluder
{
	vec4 position;
};

uniform occluderBlock
{
	occluder occluders[CLUSTER_MAX_OCCLUDERS];
};

struct decal
{
	mat4  decalMatrix;
	mat4  invDecalMatrix;
	vec4  uvScaleBias;
	vec4  posRad;
	vec4  color;
	uint  flags;
	float angleFade;
	float padding0;
	float padding1;
};

uniform decalBlock
{
	decal decals[CLUSTER_MAX_DECALS];
};

uint get_cluster_z_index(float screen_depth)
{
	return uint(max(log(screen_depth) * clusterScaleBias.x + clusterScaleBias.y, 0.0));
}

uint compute_cluster_index(vec2 pixel_pos, float screen_depth)
{
	uint z_index = get_cluster_z_index(screen_depth);
    uvec3 indices = uvec3(uvec2(pixel_pos.xy / clusterTileSizes.xy), z_index);
    uint cluster = indices.x + indices.y * CLUSTER_GRID_SIZE_X + indices.z * CLUSTER_GRID_SIZE_X * CLUSTER_GRID_SIZE_Y;
    return cluster;
}

// https://seblagarde.wordpress.com/2014/12/01/inverse-trigonometric-functions-gpu-optimization-for-amd-gcn-architecture/
// max absolute error 1.3x10^-3
// Eberly's odd polynomial degree 5 - respect bounds
// 4 VGPR, 14 FR (10 FR, 1 QR), 2 scalar
// input [0, infinity] and output [0, PI/2]
float atanPos(float x) 
{ 
    float t0 = (x < 1.0) ? x : 1.0f / x;
    float t1 = t0 * t0;
    float poly = 0.0872929;
    poly = -0.301895 + poly * t1;
    poly = 1.0f + poly * t1;
    poly = poly * t0;
    return (x < 1.0) ? poly : 1.570796 - poly;
}

// 4 VGPR, 16 FR (12 FR, 1 QR), 2 scalar
// input [-infinity, infinity] and output [-PI/2, PI/2]
float atanFast(float x) 
{     
    float t0 = atanPos(abs(x));     
    return (x < 0.0) ? -t0: t0; 
}

float acosFast(float x) 
{ 
    x = abs(x); 
    float res = -0.156583 * x + 1.570796; 
    res *= sqrt(1.0f - x); 
    return (x >= 0) ? res : 3.141592 - res; 
}

// debug view
vec3 temperature(float t)
{
    vec3 c[10] = vec3[10](
        vec3(   0.0/255.0,   2.0/255.0,  91.0f/255.0 ),
        vec3(   0.0/255.0, 108.0/255.0, 251.0f/255.0 ),
        vec3(   0.0/255.0, 221.0/255.0, 221.0f/255.0 ),
        vec3(  51.0/255.0, 221.0/255.0,   0.0f/255.0 ),
        vec3( 255.0/255.0, 252.0/255.0,   0.0f/255.0 ),
        vec3( 255.0/255.0, 180.0/255.0,   0.0f/255.0 ),
        vec3( 255.0/255.0, 104.0/255.0,   0.0f/255.0 ),
        vec3( 226.0/255.0,  22.0/255.0,   0.0f/255.0 ),
        vec3( 191.0/255.0,   0.0/255.0,  83.0f/255.0 ),
        vec3( 145.0/255.0,   0.0/255.0,  65.0f/255.0 ) 
    );

    float s = t * 10.0;

    int cur = int(s) <= 9 ? int(s) : 9;
    int prv = cur >= 1 ? cur - 1 : 0;
    int nxt = cur < 9 ? cur + 1 : 9;

    float blur = 0.8;

    float wc = smoothstep( float(cur) - blur, float(cur) + blur, s ) * (1.0 - smoothstep(float(cur + 1) - blur, float(cur + 1) + blur, s) );
    float wp = 1.0 - smoothstep( float(cur) - blur, float(cur) + blur, s );
    float wn = smoothstep( float(cur + 1) - blur, float(cur + 1) + blur, s );

    vec3 r = wc * c[cur] + wp * c[prv] + wn * c[nxt];
    return vec3( clamp(r.x, 0.0f, 1.0), clamp(r.y, 0.0, 1.0), clamp(r.z, 0.0, 1.0) );
}

// https://therealmjp.github.io/posts/sg-series-part-1-a-brief-and-incomplete-history-of-baked-lighting-representations/
// SphericalGaussian(dir) := Amplitude * exp(Sharpness * (dot(Axis, dir) - 1.0f))
struct SG
{
    vec3 Amplitude;
    vec3 Axis;
    float Sharpness;
};

SG DistributionTermSG(vec3 direction, float roughness)
{
    SG distribution;
    distribution.Axis = direction;
    float m2 = roughness * roughness;
    distribution.Sharpness = 2.0 / m2;
    distribution.Amplitude = vec3(1.0 / (3.141592 * m2));

    return distribution;
}

SG WarpDistributionSG(SG ndf, vec3 view)
{
    SG warp;
    warp.Axis = reflect(-view, ndf.Axis);
    warp.Amplitude = ndf.Amplitude;
    warp.Sharpness = ndf.Sharpness / (4.0 * max(dot(ndf.Axis, view), 0.1));
    return warp;
}

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

vec3 CalculateAmbientSpecular(vec3 normal, vec3 view, float roughness, vec3 f0)
{
	vec3 ambientSpecular = vec3(0.0);
	for(int sg = 0; sg < 8; ++sg)
	{
		SG ndf = DistributionTermSG(normal, roughness);
		SG warpedNDF = WarpDistributionSG(ndf, view);

		SG lightSG;
		lightSG.Amplitude = ambientSG[sg].xyz;
		lightSG.Axis = ambientSGBasis[sg].xyz;
		lightSG.Sharpness = ambientSGBasis[sg].w;

		float nDotL = clamp(dot(normal.xyz, warpedNDF.Axis.xyz), 0.0, 1.0);

		// NDF
		vec3 spec = SGInnerProduct(warpedNDF, lightSG);

		// no Geometry term

		// Fresnel
		vec3 h = normalize(warpedNDF.Axis + view);
		vec3 f = f0 + (1.0 - f0) * exp2(-8.35 * max(0.0, dot(warpedNDF.Axis, h)));
		//f *= clamp(dot(f0, vec3(333.0)), 0.0, 1.0); // fade out when spec is less than 0.1% albedo
		
		ambientSpecular.xyz = (spec * nDotL) * f + ambientSpecular.xyz;
	}
	return ambientSpecular;// * 3.141592;
}

// todo: split the spotlights out
void CalculatePointLighting(uint bucket_index, vec3 normal, vec3 view, vec4 shadows, vec3 albedo, vec3 f0, float roughness, inout vec3 diffuseLight, inout vec3 specularLight)
{	
	// precompute some terms
	float a = roughness;// * roughness;
	float a2 = a;// * a;
	float rcp_a2 = 1.0 / a2;
	float aperture = max(sqrt(1.0 - shadows.w), 0.01);
	vec3 reflVec = reflect(-view, normal);

	float scalar = 0.4; // todo: needs to come from rdCamera_pCurCamera->attenuationMin

	float overdraw = 0.0;

	uint first_item = firstLight;
	uint last_item = first_item + numLights - 1u;
	uint first_bucket = first_item / 32u;
	uint last_bucket = min(last_item / 32u, max(0u, CLUSTER_BUCKETS_PER_CLUSTER - 1u));
	for (uint bucket = first_bucket; bucket <= last_bucket; ++bucket)
	{
		uint bucket_bits = uint(texelFetch(clusterBuffer, int(bucket_index + bucket)).x);
		while(bucket_bits != 0u)
		{
			uint bucket_bit_index = uint(findLSB(bucket_bits));
			uint light_index = bucket * 32u + bucket_bit_index;
			bucket_bits ^= (1u << bucket_bit_index);
				
		#ifdef SPECULAR
			if (light_index >= first_item && light_index <= last_item)
		#else
			if (light_index >= first_item && light_index <= last_item && any(lessThan(diffuseLight, vec3(1.0))))
		#endif
			{
				overdraw += 1.0;

				light l = lights[light_index];
				vec3 diff = l.position.xyz - f_coord.xyz;

				float len;

				// diffuse uses dist to plane
				if (lightMode == 2)
					len = dot(l.position.xyz - f_coord.xyz, normal.xyz);
				else
					len = length(diff);

				if ( len >= l.falloffMin )
					continue;

				float rcpLen = 1.0 / max(len, 0.0001);
				diff *= rcpLen;

				float intensity = l.direction_intensity.w;
				if(l.type == 3)
				{
					float angle = dot(l.direction_intensity.xyz, diff);
					if (angle <= l.cosAngleY)
						continue;

					if (angle < l.cosAngleX)
                        intensity = (1.0 - (l.cosAngleX - angle) * l.lux) * intensity;
				}

				float lightMagnitude = dot(normal, diff);

				// this is JK's attenuation model, note it depends on scalar value matching whatever was used to calculate the intensity, it seems
				intensity = max(0.0, intensity - len * scalar);

				if(numOccluders > 0)
				{
					float localShadow = clamp(dot(shadows.xyz, diff.xyz) / aperture, 0.0, 1.0);
					lightMagnitude *= localShadow * localShadow;
				}
				
				vec3 cd;
				if (lightMode == 5)
				{
					// https://www.shadertoy.com/view/dltGWl
					vec3 sss = 0.2 * exp(-3.0 * abs(lightMagnitude) / (fillColor.xyz + 0.001));
					cd.xyz = (fillColor.xyz * sss + max(0.0, lightMagnitude));
				}
				else
				{
					cd.xyz = vec3(max(0.0, lightMagnitude));
				}

				lightMagnitude = max(lightMagnitude, 0.0);

				diffuseLight += l.color.xyz * intensity * cd;

				#ifdef SPECULAR
					vec3 h = normalize(diff + view);
					vec3 f = f0 + (1.0 - f0) * exp2(-8.35 * max(0.0, dot(diff, h)));
					//f *= clamp(dot(f0, vec3(333.0)), 0.0, 1.0); // fade out when spec is less than 0.1% albedo
					
					float c = 0.72134752 * rcp_a2 + 0.39674113;
					float d = exp2( c * dot(reflVec, diff) - c ) * (rcp_a2 / 3.141592);

					vec3 cs = f * (lightMagnitude * d);

					specularLight += l.color.xyz * intensity * cs;
				#endif
			}
			else if (light_index > last_item)
			{
				bucket = CLUSTER_BUCKETS_PER_CLUSTER;
				break;
			}
		}
	}

	//diffuseLight.rgb = temperature(overdraw * 0.125);
}

vec4 CalculateIndirectShadows(uint bucket_index, vec3 pos, vec3 normal)
{
	vec4 shadowing = vec4(normal.xyz, 1.0);
	float overdraw = 0.0;

	uint first_item = firstOccluder;
	uint last_item = first_item + numOccluders - 1u;
	uint first_bucket = first_item / 32u;
	uint last_bucket = min(last_item / 32u, max(0u, CLUSTER_BUCKETS_PER_CLUSTER - 1u));
	for (uint bucket = first_bucket; bucket <= last_bucket; ++bucket)
	//for (int occluder_index = 0; occluder_index < numOccluders; ++occluder_index)
	{
		uint bucket_bits = uint(texelFetch(clusterBuffer, int(bucket_index + bucket)).x);
		while(bucket_bits != 0u)
		{
			uint bucket_bit_index = uint(findLSB(bucket_bits));
			uint occluder_index = bucket * 32u + bucket_bit_index;
			bucket_bits ^= (1u << bucket_bit_index);
			
			if (occluder_index >= first_item && occluder_index <= last_item)
			{
				overdraw += 1.0;				
				//occluder occ = occluders[occluder_index];

				occluder occ = occluders[occluder_index - first_item];

				vec3 direction = (occ.position.xyz - pos.xyz);
				float len = length(occ.position.xyz - pos.xyz);
				if (len >= occ.position.w)
					continue;

				float rcpLen = 1.0 / max(len, 0.0001);
				direction *= rcpLen;

				float cosTheta = dot(normal, direction);
				if(cosTheta <= 0.0)
					continue;

				float solidAngle = (1.0 - cos(atanFast(occ.position.w * rcpLen)));

				// simplified smoothstep falloff, equivalent to smoothstep(0, occ.position.w, occ.position.w - len)
				float falloff = clamp((occ.position.w - len) / occ.position.w, 0.0, 1.0);
				falloff = falloff * falloff * (3.0 - 2.0 * falloff);

				float integralSolidAngle = cosTheta * solidAngle * falloff;
				shadowing.w *= 1.0 - integralSolidAngle;
				shadowing.xyz -= direction * integralSolidAngle * 0.5;
			}
			else if (occluder_index > last_item)
			{
				bucket = CLUSTER_BUCKETS_PER_CLUSTER;
				break;
			}
		}
	}
	shadowing.xyz = normalize(shadowing.xyz);
	return shadowing;
}


vec3 blackbody(float t)
{
    t *= 3000.0;
    
    float u = ( 0.860117757 + 1.54118254e-4 * t + 1.28641212e-7 * t*t ) 
            / ( 1.0 + 8.42420235e-4 * t + 7.08145163e-7 * t*t );
    
    float v = ( 0.317398726 + 4.22806245e-5 * t + 4.20481691e-8 * t*t ) 
            / ( 1.0 - 2.89741816e-5 * t + 1.61456053e-7 * t*t );

    float x = 3.0*u / (2.0*u - 8.0*v + 4.0);
    float y = 2.0*v / (2.0*u - 8.0*v + 4.0);
    float z = 1.0 - x - y;
    
    float Y = 1.0;
    float X = Y / y * x;
    float Z = Y / y * z;

    mat3 XYZtoRGB = mat3(3.2404542, -1.5371385, -0.4985314,
                        -0.9692660,  1.8760108,  0.0415560,
                         0.0556434, -0.2040259,  1.0572252);

    return max(vec3(0.0), (vec3(X,Y,Z) * XYZtoRGB) * pow(t * 0.0004, 4.0));
}

void BlendDecals(inout vec3 color, inout vec3 emissive, uint bucket_index, vec3 pos, vec3 normal)
{
	float overdraw = 0.0;

	uint first_item = firstDecal;
	uint last_item = first_item + numDecals - 1u;
	uint first_bucket = first_item / 32u;
	uint last_bucket = min(last_item / 32u, max(0u, CLUSTER_BUCKETS_PER_CLUSTER - 1u));
	for (uint bucket = first_bucket; bucket <= last_bucket; ++bucket)
	{
		uint bucket_bits = uint(texelFetch(clusterBuffer, int(bucket_index + bucket)).x);
		while(bucket_bits != 0u)
		{
			uint bucket_bit_index = uint(findLSB(bucket_bits));
			uint decal_index = bucket * 32u + bucket_bit_index;
			bucket_bits ^= (1u << bucket_bit_index);
			
			if (decal_index >= first_item && decal_index <= last_item)
			{
				decal dec = decals[decal_index - first_item];
								overdraw += 1.0;

				vec4 objectPosition = inverse(dec.decalMatrix) * vec4(pos.xyz, 1.0);				
				vec3 falloff = 0.5f - abs(objectPosition.xyz);
				if( any(lessThanEqual(falloff, vec3(0.0))) )
					continue;
				
				vec2 decalTexCoord = objectPosition.xz + 0.5;
				decalTexCoord = decalTexCoord.xy * dec.uvScaleBias.zw + dec.uvScaleBias.xy;
				
				vec4 decalColor = textureLod(decalAtlas, decalTexCoord, 0);
				
				bool isHeat = (dec.flags & 0x2u) == 0x2u;
				bool isAdditive = (dec.flags & 0x4u) == 0x4u;
				bool isRgbAlpha = (dec.flags & 0x8u) == 0x8u;
				if(isRgbAlpha)
					decalColor.a = max(decalColor.r, max(decalColor.g, decalColor.b));

				if(decalColor.a < 0.001)
					continue;
				
				decalColor.rgb *= dec.color.rgb;
				
				if(isHeat)
				{
					decalColor.rgb = blackbody(decalColor.r);
					emissive.rgb += decalColor.rgb;
				}
				
				float edgeBlend = 1.0 - pow(clamp(abs(objectPosition.z), 0.0, 1.0), 8);
				if(isAdditive)
					color.rgb += edgeBlend * decalColor.rgb;
				else
					color.rgb = mix(color.rgb, decalColor.rgb, decalColor.w * edgeBlend);
			}
			else if (decal_index > last_item)
			{
				bucket = CLUSTER_BUCKETS_PER_CLUSTER;
				break;
			}
		}
	}

	//color.rgb *= temperature(overdraw * 0.125);
}

layout(location = 0) out vec4 fragColor;
layout(location = 1) out vec4 fragColorEmiss;

float luminance(vec3 c_rgb)
{
    const vec3 W = vec3(0.2125, 0.7154, 0.0721);
    return dot(c_rgb, W);
}

vec3 normals(vec3 pos) {
    vec3 fdx = dFdx(pos);
    vec3 fdy = dFdy(pos);
    return normalize(cross(fdx, fdy));
}

mat3 construct_tbn(vec2 uv)
{
	// use face normals for this
    //vec3 n = normals(f_coord.xyz);

    vec3 dp1 = dFdx(f_coord.xyz);
    vec3 dp2 = dFdy(f_coord.xyz);
    vec2 duv1 = dFdx(uv.xy);
    vec2 duv2 = dFdy(uv.xy);

	vec3 n = normalize(cross(dp1, dp2));

    vec3 dp2perp = cross(dp2, n);
    vec3 dp1perp = cross(n, dp1);

    vec3 t = dp2perp * duv1.x + dp1perp * duv2.x;
    vec3 b = dp2perp * duv1.y + dp1perp * duv2.y;

    float invmax = inversesqrt(max(dot(t, t), dot(b, b)));
    return mat3(t * invmax, b * invmax, n);
}

vec2 parallax_mapping(vec2 tc)
{
    /*if (f_coord.x < 0.5) {
        return tc;
    }*/

	mat3 tbn = construct_tbn(tc);
	vec3 localViewDir = normalize(-f_coord.xyz);
    vec3 view_dir = normalize(transpose(tbn) * localViewDir);

    const float min_layers = 32.0;
    const float max_layers = 128.0;
    float num_layers = mix(max_layers, min_layers, abs(dot(vec3(0.0, 0.0, 1.0), view_dir)));

    float layer_depth = 1.0 / num_layers;
    float current_layer_depth = 0.0;
    vec2 shift_per_layer = (view_dir.xy / -view_dir.z) * displacement_factor;
    vec2 d_tc = shift_per_layer / num_layers;

    vec2 current_tc = tc;
    float current_sample = textureLod(displacement_map, current_tc, 0).r;

    while(current_layer_depth < current_sample) {
        current_tc -= d_tc;
        current_sample = textureLod(displacement_map, current_tc, 0).r;
        current_layer_depth += layer_depth;
    }

    vec2 prev_tc = current_tc + d_tc;

    float after_col_depth = current_sample - current_layer_depth;
    float before_col_depth = textureLod(displacement_map, prev_tc, 0).r - current_layer_depth + layer_depth;

    float a = after_col_depth / (after_col_depth - before_col_depth);
    vec2 adj_tc = mix(current_tc, prev_tc, a);

    return adj_tc;
}

float compute_mip_bias(float z_min)
{
	float mipmap_level = 0.0;
	mipmap_level = z_min < mipDistances.x ? mipmap_level : 1.0;
	mipmap_level = z_min < mipDistances.y ? mipmap_level : 2.0;
	mipmap_level = z_min < mipDistances.z ? mipmap_level : 3.0;

	// dither the mip level
	const mat4 bayerIndex = mat4(
		vec4(00.0/16.0, 12.0/16.0, 03.0/16.0, 15.0/16.0),
		vec4(08.0/16.0, 04.0/16.0, 11.0/16.0, 07.0/16.0),
		vec4(02.0/16.0, 14.0/16.0, 01.0/16.0, 13.0/16.0),
		vec4(10.0/16.0, 06.0/16.0, 09.0/16.0, 05.0/16.0)
	);
	ivec2 coord = ivec2(gl_FragCoord.xy);
	mipmap_level += bayerIndex[coord.x & 3][coord.y & 3];

	return mipmap_level;
}

#ifdef CAN_BILINEAR_FILTER
void bilinear_paletted(vec2 uv, out vec4 color, out vec4 emissive)
{
	float mip = impl_textureQueryLod(tex, uv);
	mip += compute_mip_bias(f_coord.y);
	mip = min(mip, float(numMips - 1));

	ivec2 ires = textureSize( tex, int(mip) );
	vec2  fres = vec2( ires );

	vec2 st = uv*fres - 0.5;
    vec2 i = floor( st );
    vec2 w = fract( st );

	// textureGather doesn't handle mips, need to sample manually
	// use textureLod instead of texelFetch/manual textureGather to respect sampler states
	// this should be quite cache friendly so the overhead is minimal
    float a = textureLod( tex, (i + vec2(0.5,0.5)) / fres, mip ).x;
    float b = textureLod( tex, (i + vec2(1.5,0.5)) / fres, mip ).x;
    float c = textureLod( tex, (i + vec2(0.5,1.5)) / fres, mip ).x;
    float d = textureLod( tex, (i + vec2(1.5,1.5)) / fres, mip ).x;
	
	// read the palette
	vec4 ca = texture(worldPalette, vec2(a, 0.5));
    vec4 cb = texture(worldPalette, vec2(b, 0.5));
    vec4 cc = texture(worldPalette, vec2(c, 0.5));
    vec4 cd = texture(worldPalette, vec2(d, 0.5));

    if (a == 0.0) {
        ca.a = 0.0;
    }
    if (b == 0.0) {
        cb.a = 0.0;
    }
    if (c == 0.0) {
        cc.a = 0.0;
    }
    if (d == 0.0) {
        cd.a = 0.0;
    }

	color = mix(mix(ca, cb, w.x), mix(cc, cd, w.x), w.y);

	// Makes sure light is in a sane range
    float light = clamp(f_light, 0.0, 1.0);

	// read the light palette
	a = texture(worldPaletteLights, vec2(a, light)).x;
	b = texture(worldPaletteLights, vec2(b, light)).x;
	c = texture(worldPaletteLights, vec2(c, light)).x;
	d = texture(worldPaletteLights, vec2(d, light)).x;

	ca = texture(worldPalette, vec2(a, 0.5));
    cb = texture(worldPalette, vec2(b, 0.5));
    cc = texture(worldPalette, vec2(c, 0.5));
    cd = texture(worldPalette, vec2(d, 0.5));
	
	emissive = mix(mix(ca, cb, w.x), mix(cc, cd, w.x), w.y);
}
#endif

vec3 RGBtoHSV(vec3 c)
{
    vec4 K = vec4(0.0, -1.0 / 3.0, 2.0 / 3.0, -1.0);
	vec4 p = c.g < c.b ? vec4(c.bg, K.wz) : vec4(c.gb, K.xy);
    vec4 q = c.r < p.x ? vec4(p.xyw, c.r) : vec4(c.r, p.yzx);

    float d = q.x - min(q.w, q.y);
    float e = 1.0e-10;
    return vec3(abs(q.z + (q.w - q.y) / (6.0f * d + e)), d / (q.x + e), q.x);
}

vec3 HSVtoRGB(vec3 c)
{
    vec4 K = vec4(1.0, 2.0 / 3.0, 1.0 / 3.0, 3.0);
    vec3 p = abs(fract(c.xxx + K.xyz) * 6.0 - K.www);
    return c.z * mix(K.xxx, clamp(p - K.xxx, vec3(0.0), vec3(1.0)), c.y);
}

// much thanks to Cary Knoop
// https://forum.blackmagicdesign.com/viewtopic.php?f=21&t=122108
float rolloff(float x, float cutoff, float soft)
{
    float low  = cutoff - soft;
	float high = cutoff + soft;
	
	if(x <= low)
		return x;
        
	if(x >= high)
		return cutoff;
	
	return -1.0f / (4.0f * soft) * (x * x - 2.0f * high * x + low * low);
}

void main(void)
{
    vec3 adj_texcoords = f_uv.xyz / f_uv.w;

    if(displacement_factor != 0.0)
	{
        adj_texcoords.xy = parallax_mapping(adj_texcoords.xy);
    }
	else if(uv_mode == 0)
	{
		adj_texcoords.xy = f_uv_affine;
	}

	// software actually uses the zmin of the entire face
	float mipBias = compute_mip_bias(f_coord.y);
	mipBias = min(mipBias, float(numMips - 1));

    vec4 sampled = texture(tex, adj_texcoords.xy, mipBias);
    vec4 sampledEmiss = texture(texEmiss, adj_texcoords.xy, mipBias);
    vec4 sampled_color = vec4(1.0, 1.0, 1.0, 1.0);
    vec4 vertex_color = f_color;
    float index = sampled.r;
    vec4 palval = texture(worldPalette, vec2(index, 0.5));
	vec4 emissive = vec4(0.0);

	vec3 surfaceNormals = normalize(f_normal);

    if (tex_mode == TEX_MODE_TEST || geoMode <= 3) {
		sampled_color = fillColor;
    }
    else if (tex_mode == TEX_MODE_16BPP
    || tex_mode == TEX_MODE_BILINEAR_16BPP
    )
    {
        sampled_color = vec4(sampled.b, sampled.g, sampled.r, sampled.a);
    }
    else if (tex_mode == TEX_MODE_WORLDPAL
#ifndef CAN_BILINEAR_FILTER
    || tex_mode == TEX_MODE_BILINEAR
#endif
    )

    {
#ifdef ALPHA_DISCARD
        if (index == 0.0)
            discard;
#endif

        // Makes sure light is in a sane range
        float light = clamp(f_light, 0.0, 1.0);
        float light_worldpalidx = texture(worldPaletteLights, vec2(index, light)).r;
        vec4 lightPalval = texture(worldPalette, vec2(light_worldpalidx, 0.5));

		emissive = lightPalval;
        sampled_color = palval;
    }
#ifdef CAN_BILINEAR_FILTER
    else if (tex_mode == TEX_MODE_BILINEAR)
    {
        bilinear_paletted(adj_texcoords.xy, sampled_color, emissive);
	#ifdef ALPHA_DISCARD
        if (sampled_color.a < 0.01) {
            discard;
        }
	#endif
    }
#endif

#ifdef UNLIT
	if (lightMode == 0)
		emissive.xyz *= fillColor.xyz * 0.5;
#endif

    vec4 albedoFactor_copy = albedoFactor;

	vec3 localViewDir = normalize(-f_coord.xyz);
	uint cluster_index = compute_cluster_index(gl_FragCoord.xy, f_coord.y);
	uint bucket_index = cluster_index * CLUSTER_BUCKETS_PER_CLUSTER;

	vec3 diffuseColor = sampled_color.xyz;
	vec3 specularColor = vec3(0.0);
	float roughness = 0.0;

	vec3 diffuseLight = vertex_color.xyz;
	vec3 specularLight = vec3(0.0);

#ifndef UNLIT
	#ifdef SPECULAR
		//roughness = 0.2;

		// fill color is effectively an anti-metalness control
		vec3 avgAlbedo = fillColor.xyz;
		
		// blend to metal when dark
		diffuseColor = diffuseColor * avgAlbedo;// -> 0 * (1-avgAlbedo) + diffuseColor * avgAlbedo -> mix(vec3(0.0), diffuseColor, avgAlbedo)
		
		// blend to dielectric white when bright
		specularColor = mix(sampled_color.xyz, vec3(0.5), avgAlbedo);
		
		// try to estimate some roughness variation from the texture
		float smoothness = max(sampled_color.r, max(sampled_color.g, sampled_color.b));
		roughness = mix(0.25, 0.05, min(sqrt(smoothness * 2.0), 1.0)); // don't get too rough or there's no point in using specular here
		
		// blend out really dark stuff to fill color with high roughness (ex strifle scopes)
		float threshold = 1.0 / (15.0 / 255.0);
		roughness = mix(0.05, roughness, min(smoothness * threshold, 1.0));
		//specularColor = mix(min(avgAlbedo * 2.0, vec3(1.0)), specularColor, min(smoothness * threshold, 1.0));
	#endif
#endif

	if((renderCaps & 0x4) == 0x4 && numDecals > 0u)
		BlendDecals(diffuseColor.xyz, emissive.xyz, bucket_index, f_coord.xyz, surfaceNormals);

#ifndef UNLIT
	#ifdef SPECULAR
		// let's make it happen cap'n
		specularLight.xyz += CalculateAmbientSpecular(surfaceNormals, localViewDir, roughness, specularColor.xyz);
	#endif
		
	vec4 shadows = vec4(0.0, 0.0, 0.0, 1.0);
	if ((renderCaps & 0x2) == 0x2 && numOccluders > 0u)
		shadows = CalculateIndirectShadows(bucket_index, f_coord.xyz, surfaceNormals);

	float ao = (shadows.w + 0.1) / 1.1; // remap so we don't overdarken
	diffuseLight.xyz *= ao;
	specularLight.xyz *= ao;
	
	if ((renderCaps & 0x1) == 0x1 && numLights > 0u)
		CalculatePointLighting(bucket_index, surfaceNormals, localViewDir, shadows, diffuseColor.xyz, specularColor.xyz, roughness, diffuseLight, specularLight);
	
	diffuseLight.xyz = clamp(diffuseLight.xyz, vec3(0.0), vec3(1.0));	
	specularLight.xyz = clamp(specularLight.xyz, vec3(0.0), vec3(2.0));	

	// taper off highlights
	//specularLight.r = rolloff(specularLight.r, 1.0, 0.2);
	//specularLight.g = rolloff(specularLight.g, 1.0, 0.2);
	//specularLight.b = rolloff(specularLight.b, 1.0, 0.2);
#endif

	diffuseLight.xyz *= diffuseColor.xyz;
	//specularLight.xyz *= specularColor.xyz;

	vec4 main_color = vec4(diffuseLight.xyz, vertex_color.w) + vec4(specularLight.xyz, 0.0);    
    main_color *= albedoFactor_copy;
	
	if (sampledEmiss.r != 0.0 || sampledEmiss.g != 0.0 || sampledEmiss.b != 0.0)
    {
        emissive.rgb += sampledEmiss.rgb * emissiveFactor;
    }

	main_color.rgb = max(main_color.rgb, emissive.rgb);

    float orig_alpha = main_color.a;

#ifdef ALPHA_BLEND
    if (main_color.a < 0.01 && sampledEmiss.r == 0.0 && sampledEmiss.g == 0.0 && sampledEmiss.b == 0.0) {
        discard;
    }
#endif

	
#ifdef FOG
	if(fogEnabled > 0)
	{
		float distToCam = length(-f_coord.xyz);
		float fog_amount = clamp((distToCam - fogStart) / (fogEnd - fogStart), 0.0, 1.0);
		fog_amount *= fogColor.a;

		main_color.rgb = mix(main_color.rgb, fogColor.rgb, fog_amount);
		emissive.rgb = mix(emissive.rgb, emissive.rgb, fog_amount);
	}
#endif

    fragColor = main_color;

	// dither the output in case we're using some lower precision output
	if(ditherMode == 1)
	{
		const float DITHER_LUT[16] = float[16](
				0, 4, 1, 5,
				6, 2, 7, 3,
				1, 5, 0, 4,
				7, 3, 6, 2
		);	
	
		int wrap_x = int(gl_FragCoord.x) & 3;
		int wrap_y = int(gl_FragCoord.y) & 3;
		int wrap_index = wrap_x + wrap_y * 4;
		fragColor.rgb = min(fragColor.rgb + DITHER_LUT[wrap_index] / 255.0, vec3(1.0));
	}

#ifndef ALPHA_BLEND
    fragColorEmiss = emissive;
#else
    // Dont include any windows or transparent objects in emissivity output
	fragColorEmiss = vec4(0.0);
#endif
}
